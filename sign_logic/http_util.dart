import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:get/get.dart' as GetPackage;
import 'package:image_gallery_saver/image_gallery_saver.dart';
import 'package:openim_common/openim_common.dart';
import 'package:openim_common/src/utils/app_reset_bridge.dart';
import 'package:openim_common/src/utils/sign_util.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:sprintf/sprintf.dart';
import 'package:talker_dio_logger/talker_dio_logger.dart';
import 'package:localization/localization.dart';

var dio = Dio();

enum BaseURLType {
  chatAddr,
  apiAddr,
  gateway,
}

class HttpUtil {
  HttpUtil._();
  static final MerchantController merchantController =
      GetPackage.Get.find<MerchantController>();
  static final GatewayDomainController gatewayDomainLogic =
      GetPackage.Get.find<GatewayDomainController>();

  static void init() async {
    // DataSp.clearLastSuccessGatewayDomain();
    // DataSp.clearFallbackGatewayDomains();
    PackageInfo packageInfo = await PackageInfo.fromPlatform();
    int? platform;
    String? brand;
    // add interceptors
    dio
      // ..interceptors.add(PrettyDioLogger(
      //   requestHeader: kDebugMode,
      //   requestBody: kDebugMode,
      //   responseBody: kDebugMode,
      //   responseHeader: kDebugMode,
      // ))
      ..interceptors.add(InterceptorsWrapper(
        onRequest: (options, handler) async {
          //options.headers['version'] = packageInfo.version;
          //options.headers['buildNumber'] = packageInfo.buildNumber;
          // options.headers['platform'] =
          //     platform ?? (platform = IMUtils.getPlatform());
          // options.headers["brand"] =
          //     brand ?? (brand == await DeviceInfoUtil.getDeviceInfoBrand());
          // options.headers["packageName"] = packageInfo.packageName;
          final languageCode = GetPackage.Get.locale?.languageCode;
          String? locale;
          if (languageCode == 'zh') {
            locale = 'zh-CN';
          } else if (languageCode == 'en') {
            locale = 'en-US';
          } else {
            locale = languageCode;
          }
          options.headers['Accept-Language'] = locale;

          // Add gateway signature for all requests
          try {
            final method = options.method.toUpperCase();
            final uri = options.uri;
            final path = uri.path;

            // Get device information
            final platformValue = platform ?? IMUtils.getPlatform();
            final brandValue =
                brand ?? await DeviceInfoUtil.getDeviceInfoBrand();
            final deviceId = DataSp.getDeviceID();
            String channel = options.headers['X-Channel'] ?? '';

            // Get token based on the URL
            String token = options.headers['token'] ?? 'xxx';
            if (token.isEmpty) {
              token = 'xxx';
            }

            if (channel.isEmpty) {
              channel = 'test_channel';
            }

            // Convert data to JSON string for body
            String body = '';
            if (options.data != null) {
              if (options.data is Map) {
                body = jsonEncode(options.data);
              } else if (options.data is String) {
                body = options.data;
              }
            }

            final baseURLType = options.extra['baseURLType'] as BaseURLType?;
            String secret = Config.gatewaySecret;
            if (baseURLType == BaseURLType.apiAddr || baseURLType == BaseURLType.chatAddr) {
              final merchantId = merchantController.currentMerchant.value.id;
              secret = Config.merchantSecret[merchantId] ?? Config.gatewaySecret;
            }

            // Generate signature
            final signParams = SignUtil.generateSign(
              method: method,
              path: path,
              body: body,
              secret: secret,
              platform: platformValue,
              deviceId: deviceId,
              channel: channel,
              packageName: packageInfo.packageName,
              version: packageInfo.version,
              brand: brandValue,
              buildNumber: packageInfo.buildNumber,
              token: token,
              isGateway: baseURLType == BaseURLType.gateway,
            );

            // String v = options.headers['token'];

            // if (v.isEmpty){
            //   options.headers['token'] = 'xxx';
            // }
            // Add all required headers
            options.headers['X-Platform'] = platformValue;
            options.headers['X-Device-Id'] = deviceId;
            options.headers['X-Channel'] = channel;
            options.headers['X-PackageName'] = packageInfo.packageName;
            options.headers['X-Version'] = packageInfo.version;
            options.headers['X-Brand'] = brandValue;
            options.headers['X-BuildNumber'] = packageInfo.buildNumber;
            options.headers['X-Token'] = token;
            options.headers['X-Nonce'] = signParams.nonce;
            options.headers['X-OperationId'] = signParams.operationId;
            options.headers['X-Timestamp'] = signParams.timestamp;
            options.headers['X-Signature'] = signParams.signature;
          } catch (e) {
            // If signature generation fails, continue without it
            Logger.print('Failed to generate gateway signature: $e');
          }

          return handler.next(options);
        },
      ))
      ..interceptors.add(
        TalkerDioLogger(
          settings: const TalkerDioLoggerSettings(
            printRequestHeaders: kDebugMode,
            printRequestData: kDebugMode,
            printResponseMessage: kDebugMode,
            printResponseData: kDebugMode,
            printResponseHeaders: kDebugMode,
          ),
        ),
      )
      ..interceptors.add(InterceptorsWrapper(onRequest: (options, handler) {
        print(
            '************************ merchant: ${merchantController.currentMerchant.value.name}');
        print(
            '************************ IP: ${merchantController.currentMerchant.value.ip}');

        return handler.next(options); //continue
        // 如果你想完成请求并返回一些自定义数据，你可以resolve一个Response对象 `handler.resolve(response)`。
        // 这样请求将会被终止，上层then会被调用，then中返回的数据将是你的自定义response.
        //
        // 如果你想终止请求并触发一个错误,你可以返回一个`DioError`对象,如`handler.reject(error)`，
        // 这样请求将被中止并触发异常，上层catchError会被调用。
      }, onResponse: (response, handler) {
        // Do something with response data
        return handler.next(response); // continue
        // 如果你想终止请求并触发一个错误,你可以 reject 一个`DioError`对象,如`handler.reject(error)`，
        // 这样请求将被中止并触发异常，上层catchError会被调用。
      }, onError: (DioException e, handler) {
        // Do something with response error
        return handler.next(e); //continue
        // 如果你想完成请求并返回一些自定义数据，可以resolve 一个`Response`,如`handler.resolve(response)`。
        // 这样请求将会被终止，上层then会被调用，then中返回的数据将是你的自定义response.
      }));

    // 配置dio实例
    dio.options.connectTimeout = const Duration(seconds: 30); //30s
    dio.options.receiveTimeout = const Duration(seconds: 30);
  }

  static String get operationID =>
      DateTime.now().millisecondsSinceEpoch.toString();

  static String get currentGatewayDomain =>
      gatewayDomainLogic.currentDomain.value;

  
  /// fileType: file = "1",video = "2",picture = "3"
  static Future<String> uploadImageForMinio({
    required String path,
    bool compress = true,
  }) async {
    String fileName = path.substring(path.lastIndexOf("/") + 1);
    // final mf = await MultipartFile.fromFile(path, filename: fileName);
    String? compressPath;
    if (compress) {
      File? compressFile = await FileUtils.compressImageAndGetFile(File(path));
      compressPath = compressFile?.path;
      Logger.print('compressPath: $compressPath');
    }
    final bytes = await File(compressPath ?? path).readAsBytes();
    final mf = MultipartFile.fromBytes(bytes, filename: fileName);

    var formData = FormData.fromMap({
      'operationID': '${DateTime.now().millisecondsSinceEpoch}',
      'fileType': 1,
      'file': mf
    });

    var resp = await dio.post<Map<String, dynamic>>(
      "${merchantController.currentMerchant.value.apiAddr?.trim()}/third/minio_upload",
      data: formData,
      options: Options(headers: {'token': DataSp.imToken}),
    );
    return resp.data?['data']['URL'];
  }

  ///
  static Future post(String path,
      {dynamic data,
      bool showErrorToast = true,
      Map<String, dynamic>? queryParameters,
      Options? options,
      CancelToken? cancelToken,
      ProgressCallback? onSendProgress,
      ProgressCallback? onReceiveProgress,
      bool usingSign = false,
      BaseURLType baseURLType = BaseURLType.chatAddr}) async {
    try {
      data ??= {};
      options ??= Options();
      options.headers ??= {};
      options.extra ??= {};
      options.extra!['baseURLType'] = baseURLType;
      //options.headers!['operationID'] = operationID;

      String url;
      if (path.startsWith('http')) {
        url = path;
      } else if (baseURLType == BaseURLType.apiAddr) {
        options.headers!['token'] = DataSp.imToken;
        url =
            '${merchantController.currentMerchant.value.apiAddr?.trim()}/$path';
      } else if (baseURLType == BaseURLType.gateway) {
        url = '$currentGatewayDomain/$path';
        options.headers!['token'] = DataSp.gatewayToken;
      } else {
        url =
            '${merchantController.currentMerchant.value.chatAddr?.trim()}/$path';
        options.headers!['token'] = DataSp.chatToken;
      }

      var result = await dio.post<Map<String, dynamic>>(
        url,
        data: data,
        queryParameters: queryParameters,
        options: options,
        cancelToken: cancelToken,
        onSendProgress: onSendProgress,
        onReceiveProgress: onReceiveProgress,
      );

      var resp = ApiResp.fromJson(result.data!);
      if (resp.errCode == 0) return resp.data;

      if (showErrorToast) {
        final errorMsgFromMap = ApiError.getMsg(resp.errCode);
        final fallbackMsg = resp.errMsg.isNotEmpty ? resp.errMsg : resp.errDlt;
        final displayMsg = errorMsgFromMap ?? fallbackMsg;
        IMViews.showToast(displayMsg);
      }

      return Future.error((resp.errCode, resp.errMsg, resp.data));
    } catch (error) {
      // Attempt fallback only for chat/api base URLs on timeout, and retry once

      if (error is DioException &&
          (baseURLType == BaseURLType.chatAddr ||
              baseURLType == BaseURLType.apiAddr) &&
          (error.type == DioExceptionType.connectionTimeout ||
              error.type == DioExceptionType.receiveTimeout ||
              error.type == DioExceptionType.sendTimeout)) {
        final connectivityResult = await Connectivity().checkConnectivity();
        final notNetwork = connectivityResult.contains(ConnectivityResult.none);
        if (notNetwork) {
          if (showErrorToast) IMViews.showToast(StrRes.noNetwork);

          return Future.error((StrRes.noNetwork, error.type, true));
        }

        // Load saved backup servers
        final merchant = merchantController.currentMerchant.value;
        final backups = merchant.loadIMServersFromLocal();
        if (backups.isEmpty) {
          return Future.error(('', error.type, false));
        }

        // Re-measure all backups in parallel
        await Future.wait(backups.map((g) => g.measureLatency()));
        backups.sort((a, b) {
          final aMs = a.latencyMs;
          final bMs = b.latencyMs;
          if (aMs == null && bMs == null) return 0;
          if (aMs == null) return 1;
          if (bMs == null) return -1;
          return aMs.compareTo(bMs);
        });
        final fastest = backups.firstWhere(
          (g) => g.latencyMs != null,
          orElse: () => IMServerGroup(
              wsAddr: '', apiAddr: '', chatAddr: '', adminAddr: ''),
        );
        if (fastest.wsAddr.isEmpty &&
            fastest.apiAddr.isEmpty &&
            fastest.chatAddr.isEmpty &&
            fastest.adminAddr.isEmpty) {

          return Future.error(
              ('', error.type, false));
        }
        // Switch current merchant to fastest backup and persist
        final updated = Merchant(
          id: merchant.id,
          name: merchant.name,
          fullName: merchant.fullName,
          ico: merchant.ico,
          logo: merchant.logo,
          intro: merchant.intro,
          ip: merchant.ip,
          wsAddr: fastest.wsAddr.isNotEmpty ? fastest.wsAddr : merchant.wsAddr,
          apiAddr:
              fastest.apiAddr.isNotEmpty ? fastest.apiAddr : merchant.apiAddr,
          chatAddr: fastest.chatAddr.isNotEmpty
              ? fastest.chatAddr
              : merchant.chatAddr,
          adminAddr: fastest.adminAddr.isNotEmpty
              ? fastest.adminAddr
              : merchant.adminAddr,
          imUserId: merchant.imUserId,
          level: merchant.level,
          status: merchant.status,
          licenseInfo: merchant.licenseInfo,
          imServerBackup: merchant.imServerBackup,
        );

        // Show confirmation dialog
        try {
          var confirmed = await GetPackage.Get.dialog(CustomDialog(
            title: StrRes.networkUnavailableSwitchLine,
            rightText: StrRes.switchText,
            isCenter: true,
          ));

          if (confirmed == true) {
            merchantController.updateCurrentMerchant(updated);
            AppResetBridge.requestReset(updated);
          }
        } catch (_) {}

        // Retry once against new URL
        try {
          String retryUrl;
          if (path.startsWith('http')) {
            retryUrl = path;
          } else if (baseURLType == BaseURLType.apiAddr) {
            options ??= Options();
            options.headers ??= {};
            options.headers!['token'] = DataSp.imToken;
            retryUrl = '${updated.apiAddr?.trim()}/$path';
          } else {
            options ??= Options();
            options.headers ??= {};
            options.headers!['token'] = DataSp.chatToken;
            retryUrl = '${updated.chatAddr?.trim()}/$path';
          }
          final result = await dio.post<Map<String, dynamic>>(
            retryUrl,
            data: data,
            queryParameters: queryParameters,
            options: options,
            cancelToken: cancelToken,
            onSendProgress: onSendProgress,
            onReceiveProgress: onReceiveProgress,
          );
          final resp = ApiResp.fromJson(result.data!);

          if (resp.errCode == 0) return resp.data;
          if (showErrorToast) {
            final errorMsgFromMap = ApiError.getMsg(resp.errCode);
            final fallbackMsg =
                resp.errMsg.isNotEmpty ? resp.errMsg : resp.errDlt;
            final displayMsg = errorMsgFromMap ?? fallbackMsg;
            IMViews.showToast(displayMsg);
          }
          return Future.error((resp.errCode, resp.errMsg, resp.data));
        } catch (error) {
          if (error is DioException) {
            String friendlyMessage;
            final connectivityResult = await Connectivity().checkConnectivity();
            final notNetwork = connectivityResult.contains(ConnectivityResult.none);
            switch (error.type) {
              case DioExceptionType.connectionTimeout:
              case DioExceptionType.receiveTimeout:
              case DioExceptionType.sendTimeout:
                friendlyMessage = StrRes.networkRequestTimeout;
                break;
              case DioExceptionType.connectionError:
                if (notNetwork) {
                  friendlyMessage = StrRes.noNetwork;
                } else {
                  friendlyMessage = StrRes.networkConnectionFailed;
                }
                break;
              case DioExceptionType.badResponse:
                friendlyMessage = sprintf(
                    StrRes.serverResponseError, [error.response?.statusCode]);
                break;
              case DioExceptionType.cancel:
                friendlyMessage = StrRes.requestCancelled;
                break;
              default:
                friendlyMessage = StrRes.networkRequestFailed;
                break;
            }
            if (showErrorToast) IMViews.showToast(friendlyMessage);
            return Future.error((friendlyMessage, error.type, notNetwork));
          }
          if (showErrorToast) IMViews.showToast(error.toString());
          return Future.error(error);
        }
      }

      if (error is DioException) {
        String friendlyMessage;
        final connectivityResult = await Connectivity().checkConnectivity();
        final notNetwork = connectivityResult.contains(ConnectivityResult.none);
        switch (error.type) {
          case DioExceptionType.connectionTimeout:
          case DioExceptionType.receiveTimeout:
          case DioExceptionType.sendTimeout:
            friendlyMessage = StrRes.networkRequestTimeout;
            break;
          case DioExceptionType.connectionError:
            if (notNetwork) {
              friendlyMessage = StrRes.noNetwork;
            } else {
              friendlyMessage = StrRes.networkConnectionFailed;
            }
            break;
          case DioExceptionType.badResponse:
            final statusCode = error.response?.statusCode ?? 0;
            final errMsg = (error.response?.data['errMsg'] ?? '').toString();
            if (statusCode != 0 && statusCode < 500 && errMsg.isNotEmpty) {
              IMViews.showToast(errMsg);
              return Future.error((statusCode, errMsg, null));
            }
                   
            friendlyMessage = sprintf(StrRes.serverResponseError, [error.response?.statusCode]);
            break;
          case DioExceptionType.cancel:
            friendlyMessage = StrRes.requestCancelled;
            break;
          default:
            friendlyMessage = StrRes.networkRequestFailed;
            break;
        }
        if (showErrorToast) IMViews.showToast(friendlyMessage);
        return Future.error((friendlyMessage, error.type, notNetwork));
      }
      if (showErrorToast) IMViews.showToast(error.toString());
      return Future.error(error);
    }
  }



  static Future download(
    String url, {
    required String cachePath,
    CancelToken? cancelToken,
    Function(int count, int total)? onProgress,
  }) {
    return dio.download(
      url,
      cachePath,
      options: Options(
        receiveTimeout: const Duration(minutes: 10),
      ),
      cancelToken: cancelToken,
      onReceiveProgress: onProgress,
    );
  }

  static Future saveUrlPicture(
    String url, {
    CancelToken? cancelToken,
    Function(int count, int total)? onProgress,
    VoidCallback? onCompletion,
  }) async {
    final name = url.substring(url.lastIndexOf('/') + 1);
    final cachePath = await FileUtils.createTempFile(dir: 'picture', name: name);
    var intervalDo = IntervalDo();

    return download(
      url,
      cachePath: cachePath,
      cancelToken: cancelToken,
      onProgress: (int count, int total) async {
        onProgress?.call(count, total);
        if (total == -1) {
          onCompletion?.call();
          intervalDo.drop(
              fun: () async {
                await ImageGallerySaver.saveFile(cachePath);
                IMViews.showToast(StrRes.downloadSuccessful,
                    duration: const Duration(milliseconds: 3000));
              },
              milliseconds: 1500);
        }
        if (count == total) {
          onCompletion?.call();
          final result = await ImageGallerySaver.saveFile(cachePath);
          if (result != null) {
            var tips = StrRes.downloadSuccessful;
            // if (Platform.isAndroid) {
            //   final filePath = result['filePath'].split('//').last;
            //   tips = '${StrRes.saveSuccessfully}:$filePath';
            // }
            IMViews.showToast(tips);
          }
        }
      },
    );
  }

  static Future saveImage(ui.Image image) async {
    var byteData = await image.toByteData(format: ui.ImageByteFormat.png);
    if (byteData != null) {
      Uint8List uint8list = byteData.buffer.asUint8List();
      var result =
          await ImageGallerySaver.saveImage(Uint8List.fromList(uint8list));
      if (result != null) {
        var tips = StrRes.saveSuccessfully;
        if (Platform.isAndroid) {
          final filePath = result['filePath'].split('//').last;
          tips = '${StrRes.saveSuccessfully}:$filePath';
        }
        IMViews.showToast(tips);
      }
    }
  }

  static Future saveUrlVideo(
    String url, {
    CancelToken? cancelToken,
    Function(int count, int total)? onProgress,
    VoidCallback? onCompletion,
  }) async {
    final name = url.substring(url.lastIndexOf('/') + 1);
    final cachePath = await FileUtils.createTempFile(dir: 'video', name: name);

    if (File(cachePath).existsSync()) {
      onCompletion?.call();
      return;
    }

    return download(
      url,
      cachePath: cachePath,
      cancelToken: cancelToken,
      onProgress: (int count, int total) async {
        onProgress?.call(count, total);
        if (count == total) {
          onCompletion?.call();
          final result = await ImageGallerySaver.saveFile(cachePath);
          if (result != null) {
            var tips = StrRes.saveSuccessfully;
            if (Platform.isAndroid) {
              final filePath = result['filePath'].split('//').last;
              tips = '${StrRes.saveSuccessfully}:$filePath';
            }
            IMViews.showToast(tips);
          }
        }
      },
    );
  }

  static Future saveFileToGallerySaver(File file,
      {bool showToast = true}) async {
    var tips = StrRes.saveSuccessfully;

    // TODO: file.existsSync() 存在问题，总是返回true
    // if (file.existsSync()) {
    //   if (showToast) {
    //     IMViews.showToast(tips);
    //   }
    //
    //   return;
    // }

    final result = await ImageGallerySaver.saveFile(file.path);
    if (result != null && showToast) {
      if (Platform.isAndroid) {
        final filePath = result['filePath'].split('//').last;
        tips = '${StrRes.saveSuccessfully}:$filePath';
      }
      IMViews.showToast(tips);
    }
  }
}
