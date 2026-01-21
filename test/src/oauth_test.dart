// 📦 Package imports:
import 'package:clock/clock.dart';
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_mock_adapter/http_mock_adapter.dart';
// 🌎 Project imports:
import 'package:mocktail/mocktail.dart';
import 'package:oauth_interceptor/oauth_interceptor.dart';

import '../utils/custom_request_matcher.dart';
import '../utils/fake_secure_storage.dart';

class MockRequestHandler extends Mock implements RequestInterceptorHandler {}

class MockErrorHandler extends Mock implements ErrorInterceptorHandler {}

void main() {
  group('OAuth', () {
    const tokenStorageKey = 'oauth-token';
    const refreshStorageKey = 'oauth-refresh-token';
    const expiresAtStorageKey = 'oauth-expires-at';
    const initialToken = 'abcdef';
    const nextToken = 'vwxyz';
    const initialRefreshToken = '123456';
    const nextRefreshToken = '98765';
    const expirySeconds = 36000;

    late FakeSecureStorage tokenStorage;
    late Clock clock;
    late OAuth oauth;
    late Dio dio;
    late DioAdapter adapter;

    setUp(() {
      tokenStorage = FakeSecureStorage();
      clock = Clock.fixed(DateTime(2021));
      dio = Dio();
      adapter = DioAdapter(dio: dio, matcher: const CustomRequestMatcher());
      oauth = OAuth(
        tokenUrl: 'oauth/token',
        clientId: 'id',
        clientSecret: 'secret',
        dio: dio,
        clock: clock,
        storage: tokenStorage,
      );
    });

    setUpAll(() {
      registerFallbackValue(Response(requestOptions: RequestOptions()));
      registerFallbackValue(DioException(requestOptions: RequestOptions()));
    });

    Future<void> saveToken(DateTime expiresAt) async {
      await tokenStorage.write(key: tokenStorageKey, value: initialToken);
      await tokenStorage.write(
        key: expiresAtStorageKey,
        value: expiresAt.millisecondsSinceEpoch.toString(),
      );
      await tokenStorage.write(
        key: refreshStorageKey,
        value: initialRefreshToken,
      );
    }

    group('Interceptor functions', () {
      group('Refresh - Auth token past expiry date', () {
        test('adds refreshed token request is successful', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2020, 2);
          await saveToken(expiresAt);
          adapter.onPost(
            'oauth/token',
            (server) {
              server.reply(
                200,
                <String, dynamic>{
                  'access_token': nextToken,
                  'expires_in': expirySeconds,
                  'refresh_token': nextRefreshToken,
                },
              );
            },
            data: {
              'grant_type': 'refresh_token',
              'refresh_token': initialRefreshToken,
              'client_id': 'id',
              'client_secret': 'secret',
            },
          );

          final handler = MockRequestHandler();

          await oauth.onRequest(options, handler);

          expect(
            options.headers,
            containsPair('Authorization', 'Bearer $nextToken'),
          );
          verify(() => handler.next(options)).called(1);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isTrue);
          final token = await oauth.token;
          expect(token, nextToken);
        });

        test('request proceeds without auth if token refresh returns error',
            () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2020, 2);
          await saveToken(expiresAt);

          adapter.onPost(
            'oauth/token',
            (server) {
              server.reply(
                400,
                <String, dynamic>{'error_message': 'error'},
              );
            },
            data: {
              'grant_type': 'refresh_token',
              'refresh_token': initialRefreshToken,
              'client_id': 'id',
              'client_secret': 'secret',
            },
          );

          final handler = MockRequestHandler();
          await oauth.onRequest(options, handler);

          expect(options.headers.isEmpty, true);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isFalse);
          final token = await oauth.token;
          expect(token, isNull);
        });
      });

      group('Refresh - 401 error', () {
        test('does nothing with non-401 errors', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final handler = MockErrorHandler();
          final ex = DioException(
            requestOptions: options,
            response: Response(requestOptions: options, statusCode: 400),
          );
          await oauth.onError(ex, handler);

          verifyNever(() => handler.resolve(any()));
          verify(() => handler.next(ex)).called(1);
        });

        test('adds new token and retries if refresh succeeds', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2021, 2);
          await saveToken(expiresAt);
          adapter
            ..onGet(
              '1',
              headers: {'Authorization': 'Bearer $nextToken'},
              (server) {
                server.reply(200, {});
              },
            )
            ..onPost(
              'oauth/token',
              (server) {
                server.reply(
                  200,
                  <String, dynamic>{
                    'access_token': nextToken,
                    'expires_in': expirySeconds,
                    'refresh_token': nextRefreshToken,
                  },
                );
              },
              data: {
                'grant_type': 'refresh_token',
                'refresh_token': initialRefreshToken,
                'client_id': 'id',
                'client_secret': 'secret',
              },
            );

          final handler = MockErrorHandler();

          await oauth.onError(
            DioException(
              requestOptions: options,
              response: Response(requestOptions: options, statusCode: 401),
            ),
            handler,
          );

          expect(
            options.headers,
            containsPair('Authorization', 'Bearer $nextToken'),
          );
          verify(() => handler.resolve(any())).called(1);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isTrue);
          final token = await oauth.token;
          expect(token, nextToken);
        });

        test('retry clones FormData from the initial request', () async {
          final originalData = FormData.fromMap({'1': 'a'})..finalize();
          final options = RequestOptions(
            path: '1',
            headers: <String, dynamic>{},
            data: originalData,
            method: 'POST',
          );
          final expiresAt = DateTime(2021, 2);
          await saveToken(expiresAt);
          adapter
            ..onPost(
              '1',
              headers: {'Authorization': 'Bearer $nextToken'},
              data: originalData,
              (server) {
                server.reply(200, {});
              },
            )
            ..onPost(
              'oauth/token',
              (server) {
                server.reply(
                  200,
                  <String, dynamic>{
                    'access_token': nextToken,
                    'expires_in': expirySeconds,
                    'refresh_token': nextRefreshToken,
                  },
                );
              },
              data: {
                'grant_type': 'refresh_token',
                'refresh_token': initialRefreshToken,
                'client_id': 'id',
                'client_secret': 'secret',
              },
            );

          final handler = MockErrorHandler();

          await oauth.onError(
            DioException(
              requestOptions: options,
              response: Response(requestOptions: options, statusCode: 401),
            ),
            handler,
          );

          expect(
            options.headers,
            containsPair('Authorization', 'Bearer $nextToken'),
          );
          verify(
            () => handler.resolve(
              any(
                that: isA<Response>().having(
                  (res) => res.requestOptions.data,
                  'request data',
                  isA<FormData>()
                      .having(
                        (data) => data.hashCode,
                        'isNotEqual',
                        isNot(originalData.hashCode),
                      )
                      .having(
                        (data) => data.fields,
                        'fields',
                        equals(originalData.fields),
                      )
                      .having(
                        (data) => data.files,
                        'files',
                        equals(originalData.files),
                      ),
                ),
              ),
            ),
          ).called(1);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isTrue);
          final token = await oauth.token;
          expect(token, nextToken);
        });

        test('returns old error if token is null on retry', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2021, 2);
          await saveToken(expiresAt);
          adapter
            ..onGet(
              '1',
              headers: {'Authorization': 'Bearer $nextToken'},
              (server) {
                server.reply(200, {});
              },
            )
            ..onPost(
              'oauth/token',
              (server) {
                server.reply(
                  200,
                  <String, dynamic>{
                    'access_token': null,
                    'expires_in': expirySeconds,
                    'refresh_token': nextRefreshToken,
                  },
                );
              },
              data: {
                'grant_type': 'refresh_token',
                'refresh_token': initialRefreshToken,
                'client_id': 'id',
                'client_secret': 'secret',
              },
            );

          final handler = MockErrorHandler();

          await oauth.onError(
            DioException(
              requestOptions: options,
              response: Response(
                requestOptions: options,
                statusCode: 401,
                statusMessage: 'Error!',
              ),
            ),
            handler,
          );
          verifyNever(() => handler.resolve(any()));
          verify(
            () => handler.next(
              any(
                that: isA<DioException>().having(
                  (ex) => ex.response?.statusMessage,
                  'message',
                  'Error!',
                ),
              ),
            ),
          ).called(1);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isFalse);
          final token = await oauth.token;
          expect(token, isNull);
        });

        test('returns new error if retry fails', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2021, 2);
          await saveToken(expiresAt);
          adapter
            ..onGet(
              '1',
              headers: {'Authorization': 'Bearer $nextToken'},
              (server) {
                server.reply(400, {}, statusMessage: 'Error!');
              },
            )
            ..onPost(
              'oauth/token',
              (server) {
                server.reply(
                  200,
                  <String, dynamic>{
                    'access_token': nextToken,
                    'expires_in': expirySeconds,
                    'refresh_token': nextRefreshToken,
                  },
                );
              },
              data: {
                'grant_type': 'refresh_token',
                'refresh_token': initialRefreshToken,
                'client_id': 'id',
                'client_secret': 'secret',
              },
            );

          final handler = MockErrorHandler();

          await oauth.onError(
            DioException(
              requestOptions: options,
              response: Response(requestOptions: options, statusCode: 401),
            ),
            handler,
          );

          expect(
            options.headers,
            containsPair('Authorization', 'Bearer $nextToken'),
          );
          verify(
            () => handler.next(
              any(
                that: isA<DioException>().having(
                  (ex) => ex.response?.statusMessage,
                  'message',
                  'Error!',
                ),
              ),
            ),
          ).called(1);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isTrue);
          final token = await oauth.token;
          expect(token, nextToken);
        });

        test('returns original error if refresh fails', () async {
          final options =
              RequestOptions(path: '1', headers: <String, dynamic>{});
          final expiresAt = DateTime(2021, 2);
          await saveToken(expiresAt);

          adapter.onPost(
            'oauth/token',
            (server) {
              server.reply(
                400,
                <String, dynamic>{'error_message': 'error'},
              );
            },
            data: {
              'grant_type': 'refresh_token',
              'refresh_token': initialRefreshToken,
              'client_id': 'id',
              'client_secret': 'secret',
            },
          );

          final handler = MockErrorHandler();
          final ex = DioException(
            requestOptions: options,
            response: Response(requestOptions: options, statusCode: 401),
          );
          await oauth.onError(ex, handler);

          verifyNever(() => handler.resolve(any()));
          verify(() => handler.next(ex)).called(1);

          expect(options.headers.isEmpty, true);
          final signedIn = await oauth.isSignedIn;
          expect(signedIn, isFalse);
          final token = await oauth.token;
          expect(token, isNull);
        });
      });

      test('adds user token if one is present and has not expired', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});

        final expiresAt = DateTime(2021, 2);

        await saveToken(expiresAt);

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          containsPair('Authorization', 'Bearer $initialToken'),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token = await oauth.token;
        expect(token, initialToken);
      });

      test('adds nothing if no token is present', () async {
        final options = RequestOptions(path: '1', headers: <String, dynamic>{});

        await tokenStorage.deleteAll();

        final handler = MockRequestHandler();

        await oauth.onRequest(options, handler);

        expect(
          options.headers,
          isNot(contains('Authorization')),
        );
        verify(() => handler.next(options)).called(1);
        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });

    group('Login function', () {
      test('stores access token if login is successful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              200,
              <String, dynamic>{
                'access_token': initialToken,
                'expires_in': expirySeconds,
                'refresh_token': initialRefreshToken,
              },
            );
          },
          data: {
            'grant_type': 'password',
            'username': 'test@test.com',
            'password': 'P4ssword',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await oauth.login(
          PasswordGrant(username: 'test@test.com', password: 'P4ssword'),
        );

        final token = await tokenStorage.read(key: tokenStorageKey);
        final refreshToken = await tokenStorage.read(key: refreshStorageKey);
        final expiresAtMillis =
            await tokenStorage.read(key: expiresAtStorageKey);
        expect(token, initialToken);
        expect(refreshToken, initialRefreshToken);
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, expirySeconds).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, initialToken);
      });

      test('does not store token if login request is unsuccessful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              400,
              <String, dynamic>{'error_message': 'error'},
            );
          },
          data: {
            'grant_type': 'password',
            'username': 'test@test.com',
            'password': 'P4ssword',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await expectLater(
          oauth.login(
            PasswordGrant(username: 'test@test.com', password: 'P4ssword'),
          ),
          throwsA(isA<DioException>()),
        );

        final hasToken = await tokenStorage.containsKey(key: tokenStorageKey);
        expect(hasToken, isFalse);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });

    group('Client login function', () {
      test('stores access token if login is successful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              200,
              <String, dynamic>{
                'access_token': initialToken,
                'expires_in': expirySeconds,
                'refresh_token': initialRefreshToken,
              },
            );
          },
          data: {
            'grant_type': 'client_credentials',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await oauth.login(const ClientCredentialsGrant());

        final token = await tokenStorage.read(key: tokenStorageKey);
        final refreshToken = await tokenStorage.read(key: refreshStorageKey);
        final expiresAtMillis =
            await tokenStorage.read(key: expiresAtStorageKey);
        expect(token, initialToken);
        expect(refreshToken, initialRefreshToken);
        final expectedExpiresAt =
            DateTime(2021, 1, 1, 0, 0, expirySeconds).millisecondsSinceEpoch;
        expect(int.parse(expiresAtMillis!), expectedExpiresAt);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isTrue);
        final token2 = await oauth.token;
        expect(token2, initialToken);
      });

      test('does not store token if login request is unsuccessful', () async {
        adapter.onPost(
          'oauth/token',
          (server) {
            server.reply(
              400,
              <String, dynamic>{'error_message': 'error'},
            );
          },
          data: {
            'grant_type': 'client_credentials',
            'client_id': 'id',
            'client_secret': 'secret',
          },
        );

        await expectLater(
          oauth.login(const ClientCredentialsGrant()),
          throwsA(isA<DioException>()),
        );

        final hasToken = await tokenStorage.containsKey(key: tokenStorageKey);
        expect(hasToken, isFalse);

        final signedIn = await oauth.isSignedIn;
        expect(signedIn, isFalse);
        final token = await oauth.token;
        expect(token, isNull);
      });
    });
  });
}
