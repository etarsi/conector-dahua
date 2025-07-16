# _*_ coding:utf-8 _*_

from ctypes import *
from SDK_Struct import *


#  断线回调函数;Network disconnection callback function
#  参数列表(param list)：
#      lLoginID:登录句柄; Login handle
#      pchDVRIP:IP地址;IP address
#      nDVRPort:端口号;Port
#      dwUser:用户数据;user data
fDisConnect = CB_FUNCTYPE(None, C_LLONG, c_char_p, c_long, C_LDWORD)

#  断线重连回调函数;network re-connection callback function
#  参数列表(param list)：
#      lLoginID:登录句柄; Login handle
#      pchDVRIP:IP地址;IP address
#      nDVRPort:端口号;Port
#      dwUser:用户数据;user data
fHaveReConnect = CB_FUNCTYPE(None, C_LLONG, c_char_p, c_long, C_LDWORD)

#  SDK日志回调函数;SDK log callback
#  参数列表(param list)：
#      szLogBuffer:日志缓冲;log buffer
#      nLogSize:日志长度;log size
#      dwUser:用户数据;user data
fSDKLogCallBack = CB_FUNCTYPE(c_int, c_char_p, c_uint, C_LDWORD)

#  异步搜索设备回调函数;Asynchronism search device call
#  参数列表(param list):
#      lSearchHandle：搜索句柄;Search device handle
#      pDevNetInfo:设备信息;Device info
#      pUserData:用户数据信息;User data
fSearchDevicesCBEx = CB_FUNCTYPE(None, C_LLONG, POINTER(DEVICE_NET_INFO_EX2), c_void_p)

#  搜索设备回调函数;Asynchronism search device call
#  参数列表(param list):
#      pDevNetInfo:设备信息;Device info
#      pUserData:用户数据信息;User data
fSearchDevicesCB = CB_FUNCTYPE(None, POINTER(DEVICE_NET_INFO_EX), c_void_p)

#  智能分析数据回调; # intelligent analysis data callback
#  参数列表(param list):
#      lAnalyzerHandle：RealLoadPictureEx接口返回的句柄; handle of RealLoadPictureEx return
#      dwAlarmType:EM_EVENT_IVS_TYPE事件类型; EM_EVENT_IVS_TYPE event type
#      pAlarmInfo:事件信息; event information
#      pBuffer:图片数据缓存; picture buffer
#      dwBufSize:图片数据缓存大小; picture buffer size
#      dwUser:RealLoadPictureEx输入的用户数据信息; user data from RealLoadPictureEx function
#      nSequence:表示上传的相同图片情况,为0时表示是第一次出现,为2表示最后一次出现或仅出现一次,为1表示此次之后还有; instruct the repeat picture's station,0 instruct the first time it appear, 2 instruct the last time it appear or it only appear once,1 instruct it will appear next time
#      reserved:int nState = (int)reserved 表示当前回调数据的状态, 为0表示当前数据为实时数据,为1表示当前回调数据是离线数据,为2时表示离线数据传送结束; int nState = (int) reserved means current callback data status;when it is 1, it means current data is real time and current callback data is offline;when it is 2,it means offline data send structure
fAnalyzerDataCallBack = CB_FUNCTYPE(None, C_LLONG, C_DWORD, c_void_p, POINTER(c_ubyte), C_DWORD, C_LDWORD, c_int, c_void_p)

#  抓图回调函数原形(pBuf内存由SDK内部申请释放) ；Snapshot callback function original shape
#  参数列表(param list):
#      lLoginID：登录句柄; Login handle
#      pBuf:图片缓存；picture data buffer
#      RevLen:图片大小；picture len
#      EncodeType:编码类型，10：表示jpeg图片 0：mpeg4的i帧；Encode type,10: jpeg 0: number i frame of mpeg4
#      CmdSerial:请求填的序号；Serial
#      dwUser:SetSnapRevCallBack接口输入的用户数据信息; user data from SetSnapRevCallBack function
fSnapRev = CB_FUNCTYPE(None, C_LLONG, POINTER(c_ubyte), c_uint, c_uint, C_DWORD, C_LDWORD)

#  消息回调函数原形(pBuf内存由SDK内部申请释放) ；Alarm message callback function original shape(pBuf memory was managed by SDK )
#  参数列表(param list):
#      lCommand：报警类型；alarm type
#      lLoginID:登录句柄; Login handle
#      pBuf:报警信息；alarm info
#      dwBufLen:报警信息大小；alarm info len
#      pchDVRIP:IP地址;IP address
#      nDVRPort:端口号;Port
#      bAlarmAckFlag:TRUE,该事件为可以进行确认的事件；FALSE,该事件无法进行确认;TRUE,the event is affirmable event;FALSE,the event is not affirmable event
#      nEventID:用于对 AlarmAck 接口的入参进行赋值,当 bAlarmAckFlag 为 TRUE 时,该数据有效；nEventID is used by AlarmAck interface, when bAlarmAckFlag is TRUE, this data is efficient
#      dwUser:SetDVRMessCallBackEx1接口输入的用户数据信息; user data from SetDVRMessCallBackEx1 function
fMessCallBackEx1 = CB_FUNCTYPE(None, c_long, C_LLONG, POINTER(c_char), C_DWORD, POINTER(c_char), c_long, c_int, c_long, C_LDWORD)

#  回放进度回调函数; play back progress callback
#  参数列表(param list):
#      lPlayHandle：RealLoadPictureEx接口返回的句柄; handle of RealLoadPictureEx return
#      dwTotalSize: 下载数据总大小； total size of this download
#      dwDownLoadSize: 当前已下载数据的大小，dwDownLoadSize == -1 表示用户回放或者下载进度完成，dwDownLoadSize ==- 2 表示用户没有回放或者下载操作权限； current download size，-1:playback has over，-2:write file failed
#      dwUser:用户数据； user data
fDownLoadPosCallBack = CB_FUNCTYPE(None, C_LLONG, C_DWORD, C_DWORD, C_LDWORD)

#  回放数据回调; Playback data callback function
#  若设备传过来的码流是不加密的,dwDataType:0-不加密的录像文件原始数据
#  若设备传过来的码流是加密的,dwDataType: 0-解密后的私有码流(帧数据）,2-加密的原始码流
#  If the stream is unencrypted,dwDataType:0-the original unencrypted stream
#  If the stream is encrypted,dwDataType: 0-the decrypted stream(the frame data),2-the original encrypted stream
#   Whether the stream is encrypted,should call CLIENT_GetConfig(NET_EM_CFG_MEDIA_ENCRYPT) to get it;
#    If bKeyFrameEncryptEnable is TRUE,it means the stream is encrypted, otherwise it means the stream is unencrypted;
#    If you want to tramsmit the original stream,Before call playaback interface,you should call CLIENT_GetConfig(NET_EM_CFG_MEDIA_ENCRYPT) to know whether the stream is encrypted.
#    If the stream is encrypted, then should call CLIENT_AttachVK to attach VK info, At last should call CLIENT_GetVK to Get VK info.
#  参数列表(param list):
#      lRealHandle：回放数据句柄; playback handle
#      dwDataType:数据类型； data type
#      pBuffer:数据缓冲区，内存由SDK内部申请释放; data buffer, memory malloc or free was managed by SDK interior
#      dwBufSize:数据缓存大小； pBuffer's size
#      dwUser:用户数据； user data
fDataCallBack = CB_FUNCTYPE(c_int, C_LLONG, C_DWORD, POINTER(c_ubyte), C_DWORD, C_LDWORD)

#  按时间回放进度回调函数; Playback process by time callback function original shape
#  参数列表(param list):
#      lPlayHandle：RealLoadPictureEx接口返回的句柄; handle of RealLoadPictureEx return
#      dwTotalSize: 下载数据总大小； total size of this download
#      dwDownLoadSize: 当前已下载数据的大小； current download size
#      index: 文件序列; file index
#      recordfileinfo: 录像文件信息; record file information
#      dwUser:用户数据； user data
fTimeDownLoadPosCallBack = CB_FUNCTYPE(None, C_LLONG, C_DWORD, C_DWORD, c_int, NET_RECORDFILE_INFO, C_LDWORD)

#  实时预览数据回调函数原形--扩展(pBuffer内存由SDK内部申请释放); Real-time monitor data callback function original shape---extensive
#  通过 dwDataType 过滤得到对应码流，具体码流类型请参考 EM_REALDATA_FLAG; Obtain corresponding stream by filtering dwDataType, stream type refers to EM_REALDATA_FLAG
#  转码流时 dwDataType 值请参考 NET_DATA_CALL_BACK_VALUE 说明; The dwDataType value in stream transcoding refers to NET_DATA_CALL_BACK_VALUE
#  参数列表(param list):
#      lRealHandle：预览句柄; monitor handle
#      dwDataType: 回调数据类型；callback data type
#      pBuffer: 回调数据缓存； byte array, length is dwBufSize
#      dwBufSize: 回调数据的缓存大小; pBuffer's size
#      param: 参数结构体的指针; pointer to parameter structure,based on different type
#      dwUser:用户数据； user data
fRealDataCallBackEx = CB_FUNCTYPE(None, C_LLONG, C_DWORD, POINTER(c_byte), C_DWORD, C_LLONG, C_LDWORD)

#  实时预览数据回调函数原形--扩展(pBuffer内存由SDK内部申请释放); Obtain corresponding stream by filtering dwDataType, stream type refers to EM_REALDATA_FLAG
#  通过 dwDataType 过滤得到对应码流，具体码流类型请参考 EM_REALDATA_FLAG; 转码流时 dwDataType 值请参考 NET_DATA_CALL_BACK_VALUE 说明; The dwDataType value in stream converting refers to NET_DATA_CALL_BACK_VALUE
#  当转码流时，param 为具体的转码信息（视频帧、音频帧等信息），对应结构体 NET_STREAMCONVERT_INFO; when convert stream, param refers to frame info(video frame info or audio frame info), param's type is NET_STREAMCONVERT_INFO
#  参数列表(param list):
#      lRealHandle：预览句柄; monitor handle
#      dwDataType: 回调数据类型；callback data type
#      pBuffer: 回调数据缓存； byte array, length is dwBufSize
#      dwBufSize: 回调数据的缓存大小; pBuffer's size
#      param: 参数结构体的指针; pointer to parameter structure,based on different type
#      dwUser:用户数据； user data
fRealDataCallBackEx2 = CB_FUNCTYPE(None, C_LLONG, C_DWORD, POINTER(c_byte), C_DWORD, C_LLONG, C_LDWORD)

#  decoding callback function.
#  参数列表(param list):
#      nPort：channel no
#      pBuf: A/V data after decoding
#      nSize: pBuf length of A/V data after decoding
#      pFrameInfo: image and audio, refer to FRAME_INFO structure
#      pUserData: User defined data
#      nReserved2: reserved parameter
fDecCBFun = CB_FUNCTYPE(None, c_int, c_void_p, c_int, POINTER(PLAY_FRAME_INFO), c_void_p, c_int)

#  视频统计摘要信息回调函数原形;video statistical summary callback function type
#  参数列表(param list):
#      lAttachHandle：AttachVideoStatSummary 返回值;lAttachHandle is the return value of AttachVideoStatSummary
#      pBuf: 视频统计摘要数据;videostate summary data
#      dwBufLen: 视频统计摘要数据大小;videostate summary data len
#      dwUser:用户数据;User data
fVideoStatSumCallBack = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_VIDEOSTAT_SUMMARY), C_DWORD, C_LDWORD)

#  视频抓图回调函数; video data callback
#  参数列表(param list):
#      nPort：通道号;Port number
#      pBuf: 返回图像数据;Video data buffer
#      nSize: 返回图像数据大小;video data size
#      nWidth: 画面宽，单位像素;Image width. Unit is pixel
#      nHeight:画面高，单位像素;Image height. Unit is pixel
#      nStamp:时标信息，单位毫秒;Time mark information. Unit is ms
#      nType:数据类型，T_RGB32，T_UYVY，详见宏定义说明;Data type. T_RGB32, T_UYVY. Please refer to macro definition
#      nReceaved:对应用户自定义参数;Reserved
fDisplayCBFun = CB_FUNCTYPE(None, c_int, c_void_p, c_int, c_int, c_int, c_int, c_int, c_void_p)

#  订阅云台元数据接口回调函数原型; Subscribe to PTZ metadata interface and callback function prototypes
#  参数列表(param list):
#      lLoginID：登录句柄; Login handle
#      lAttachHandle: AttachPTZStatusProc 返回值;lAttachHandle is the return value of AttachPTZStatusProc
#      pBuf: 返回图像数据，现阶段主要为 SDK_PTZ_LOCATION_INFO 类型; Video data buffer，at this stage mainly SDK_PTZ_LOCATION_INFO type
#      nBufLen: 返回图像数据大小;video data size
#      dwUser:用户数据;User data
fPTZStatusProcCallBack = CB_FUNCTYPE(None, C_LLONG, C_LLONG, c_void_p, c_int, C_LDWORD)

#  温度分布数据状态回调函数;Temperature distribution data status callback function
#  参数列表(param list):
#      lAttachHandle: [OUT] 订阅句柄, CLIENT_RadiometryAttach 的返回值
#      pBuf: 热图数据信息; Heat map data information
#      nBufLen: 状态信息长度; Status information length
#      dwUser: 用户数据; user data
fRadiometryAttachCB = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_RADIOMETRY_DATA), c_int, C_LDWORD)

#  侦听服务器回调函数原形; Listening server callback function original shape
#  参数列表(param list):
#      lHandle：订阅句柄;Handle
#      pIp: 设备IP;device IP
#      wPort: 设备端口;device port
#      lCommand: 命令类型,参考EM_AUTOREGISTER_TYPE; command type, refers to EM_AUTOREGISTER_TYPE
#      pParam: 回调数据缓存； byte array, length is dwBufSize
#      dwParamLen: 回调数据的缓存大小; pBuffer's size
#      dwUserData: 用户数据; User data
fServiceCallBack = CB_FUNCTYPE(c_int, C_LLONG, c_char_p, c_ushort, C_ENUM, c_void_p, C_DWORD, C_LDWORD)

# 
fDataCallBackEx = CB_FUNCTYPE(c_int, C_LLONG, POINTER(NET_DATA_CALL_BACK_INFO), C_LDWORD)

#  透明串口回调函数原形(pBuffer内存由SDK内部申请释放)
#  Transparent COM callback function original shape
fTransComCallBack = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(c_char), C_DWORD, C_LDWORD)

#  智能分析状态订阅函数原型, lAttachHandle 为 CLIENT_AttachAnalyseTaskState 函数的返回值
#  callback function of attach analyse state, lAttachHandle is returned by interface CLIENT_AttachAnalyseTaskStat
fAnalyseTaskStateCallBack = CB_FUNCTYPE(c_int, C_LLONG, POINTER(NET_CB_ANALYSE_TASK_STATE_INFO), C_LDWORD)

#  智能分析状态订阅函数原型, lAttachHandle 是 CLIENT_AttachAnalyseTaskResult接口的返回值
#  callback function of attach analyse result, lAttachHandle is returned by CLIENT_AttachAnalyseTaskResult
fAnalyseTaskResultCallBack = CB_FUNCTYPE(c_int, C_LLONG, POINTER(NET_CB_ANALYSE_TASK_RESULT_INFO), POINTER(c_char), C_DWORD, C_LDWORD)

#  CLIENT_AttachStatusRTMPManager 入参的回调函数
#  CLIENT_AttachStatusRTMPManager Callback function with input parameters
fRTMPAttachStatusCallBack = CB_FUNCTYPE(c_int, C_LLONG, POINTER(NET_CB_RTMP_STATUS_INFO), C_LDWORD)

#  升级设备程序回调函数原形支持G以上升级文件
#  nTotalSize = 0, nSendSize = -1 表示升级完成
#  nTotalSize = 0, nSendSize = -2 表示升级出错
#  nTotalSize = 0, nSendSize = -3 用户没有权限升级
#  nTotalSize = 0, nSendSize = -4 升级程序版本过低
#  nTotalSize = -1, nSendSize = XX 表示升级进度
#  nTotalSize = XX, nSendSize = XX 表示升级文件发送进度
#  Upgrade device callback function original shape, support large file upgrade for example G bytes file.
#  nTotalSize = 0, nSendSize = -1 Indicates Upgrade Finish
#  nTotalSize = 0, nSendSize = -2 Indicates Upgrade Failed
#  nTotalSize = 0, nSendSize = -3 User do not have permission to upgrade
#  nTotalSize = 0, nSendSize = -4 Upgrade version  too low
#  nTotalSize = -1, nSendSize = XX Indicates Upgrade Progress
#  nTotalSize = XX, nSendSize = XX Upgrade file transmission progress
fUpgradeCallBackEx = CB_FUNCTYPE(None, C_LLONG, C_LLONG, c_int64, c_int64, C_LDWORD)

#  雷达报警点信息回调函数指针
#  radar alarm point info callback
fRadarAlarmPointInfoCallBack = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_RADAR_NOTIFY_ALARMPOINTINFO), C_DWORD, c_void_p, C_LDWORD)

#  回调函数
#  callback
fFaceFindState = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_CB_FACE_FIND_STATE), c_int, C_LDWORD)

#  VK信息回调(pBuffer内存由SDK内部申请释放),dwError值可以dhnetsdk.h中找到相应的解释,比如NET_NOERROR,NET_ERROR_VK_INFO_DECRYPT_FAILED等
#  VK info callback,dwError value will be finded in dhnetsdk.h,for example:NET_NOERROR,NET_ERROR_VK_INFO_DECRYPT_FAILED
fVKInfoCallBack = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_VKINFO), C_DWORD, C_LDWORD, c_void_p)

#  回放数据原始回调函数原形
#  pBuffer: 数据缓冲区，内存由SDK内部申请释放
#  无论设备传的码流是不是加密的，都回调原始码流
#  Playback data callback function prototype
#  pBuffer: data buffer, memory malloc or free was managed by SDK interior
#  Whether the stream is encrypted or not,dwDataType: 0-original stream
fOriDataCallBack = CB_FUNCTYPE(c_int, C_LLONG, C_DWORD, POINTER(C_BYTE), C_DWORD, C_LDWORD)

#  刻录设备回调函数原形, 每次1条,pBuf->dwSize == nBufLen
#  burning device callback function, pBuf->dwSize == nBufLen
fAddFileStateCB = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_CB_ADDFILESTATE), c_int, C_LDWORD)

#  订阅大图检测小图进度回调函数原型
#  the callback function of detection small image form the large image
fMultiFaceDetectState = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_CB_MULTIFACE_DETECT_STATE), C_LDWORD)

#  订阅大图检测小图进度回调函数原型
#  The callback function about attach to large image to detect small image
fMultiFaceDetectStateEx = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_CB_MULTIFACE_DETECT_STATE_EX), C_LDWORD)

#  订阅无线对码信息回调函数原形,lAttachHandle是CLIENT_AttachLowRateWPAN返回值
#  Order wireless code info call function origin, lAttachHandle is CLIENT_AttachLowRateWPAN return valud
fAttachLowRateWPANCB = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_CODEID_INFO), C_ENUM, C_LDWORD)

#  接口(CLIENT_StartTrafficFluxStat)回调
#  CLIENT_StartTrafficFluxStat's callback function
fFluxStatDataCallBack = CB_FUNCTYPE(c_int, C_LLONG, C_DWORD, c_void_p, POINTER(C_BYTE), C_DWORD, C_LDWORD, c_int, c_void_p)

#  智能分析结果的回调函数
#  attach Traffic Flow Stat Real Flow callback
#  Param List:
#      lAttachHandle: [out] lAttachHandle 订阅句柄; [out] lAttachHandle : analyse proc handle
#      pstuVehicleInOutAnalyseProc: [out] pstuVideoAnalyseTrackProc 智能分析结果的信息; [out] pstuVehicleInOutAnalyseProc : Callback information
#      dwUser: [out] dwUser 用户信息; [out] dwUser User Info
#  Return Value:
#      void; void
fVehicleInOutAnalyseProc = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_VEHICLE_INOUT_ANALYSE_PROC), C_LDWORD)

#  订阅人群分布图实时统计信息回调函数原型
#  Crowd Distri Map callback
fCrowdDistriStream = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_CB_CROWD_DISTRI_STREAM_INFO), C_LDWORD)

#  语音对讲的音频数据回调函数原形
#  Audio data of audio talk callback function
fAudioDataCallBackEx = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_AUDIO_DATA_CB_INFO), C_ENUM, C_LDWORD)

#  音频文件发送进度回调函数
#  audio file send progress callback function
fTalkSendPosCallBack = CB_FUNCTYPE(None, C_LLONG, C_DWORD, C_DWORD, C_LDWORD)

#   订阅485实时数据接口回调函数原型, lAttachHandle 为 CLIENT_AttachIotboxComm 接口的返回值;Subscribe to 485 real-time data interface callback Function prototype, lAttachHandle is the return value of CLIENT_AttachIotboxComm
#   :paramlAttachHandle 订阅句柄
#   :parampstuIotboxComm 订阅的485实时数据;pstuIotboxComm Subscribed 485 real-time data
#   :paramdwUser 用户信息;dwUser user information
fNotifyIotboxRealdata = CB_FUNCTYPE(None, C_LLONG, POINTER(NET_NOTIFY_IOTBOX_COMM), C_LDWORD)

#   解码回调函数;the call back function type for decode of frame
fDecCallBack = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_FRAME_DECODE_INFO), POINTER(NET_FRAME_INFO_EX), C_LDWORD, C_LLONG)

#   TTLV异步搜索设备回调(pDevNetInfo内存由SDK内部申请释放);TTLV Asynchronism search device call
fSearchDevicesCBTTLV = CB_FUNCTYPE(None, C_LLONG, POINTER(DEVICE_NET_INFO_TTLV), c_void_p)

#   订阅监测点位信息回调函数原型;order monitor spot info  callback prototype
fSCADAAttachInfoCallBack = CB_FUNCTYPE(None, C_LLONG, C_LLONG, POINTER(NET_SCADA_NOTIFY_POINT_INFO_LIST), c_int, C_LDWORD)

