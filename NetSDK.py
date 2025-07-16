# _*_ coding:utf-8 _*_

from SDK_Struct import *
from SDK_Enum import *
from SDK_Callback import *

error_code = {
    -1: 'Unknown error',
    0: 'No error',
    1: 'system error',
    2: 'Protocol error it may result from network timeout',
    3: 'Device protocol does not match',
    4: 'Handle is invalid',
    5: 'Failed to open channel',
    6: 'Failed to close channel',
    7: 'User parameter is illegal',
    8: 'SDK initialization error',
    9: 'SDK clear error',
    10: 'Error occurs when apply for render resources.',
    11: 'Error occurs when opening the decoder library',
    12: 'Error occurs when closing the decoder library',
    13: 'The detected channel number is 0 in multiple-channel preview.',
    14: 'Failed to initialize record library',
    15: 'The record library has not been initialized',
    16: 'Error occurs when sending out audio data',
    17: 'The real-time has been protected.',
    18: 'The real-time data has not been save.',
    19: 'Error occurs when opening the file.',
    20: 'Failed to enable PTZ to control timer.',
    21: 'Error occurs when verify returned data.',
    22: 'There is no sufficient buffer.',
    23: 'The current SDK does not support this funcntion.',
    24: 'There is no searched result.',
    25: 'You have no operation right.',
    26: 'Can not operate right now.',
    27: 'There is no audio talk channel.',
    28: 'There is no audio.',
    29: 'The network SDK has not been initialized.',
    30: 'The download completed.',
    31: 'There is no searched result.',
    32: 'Failed to get system property setup.',
    33: 'Failed to get SN.',
    34: 'Failed to get general property.',
    35: 'Failed to get DSP capacity description.',
    36: 'Failed to get network channel setup.',
    37: 'Failed to get channel name.',
    38: 'Failed to get video property.',
    39: 'Failed to get record setup',
    40: 'Failed to get decoder protocol name',
    41: 'Failed to get 232 COM function name.',
    42: 'Failed to get decoder property',
    43: 'Failed to get 232 COM setup',
    44: 'Failed to get external alarm input setup',
    45: 'Failed to get motion detection alarm',
    46: 'Failed to get device time',
    47: 'Failed to get preview parameter',
    48: 'Failed to get audio maintenance setup',
    49: 'Failed to get video matrix setup',
    50: 'Failed to get privacy mask zone setup',
    51: 'Failed to get video watermark setup',
    52: 'Failed to get config, omulticast port by channel',
    55: 'Failed to modify general property',
    56: 'Failed to modify channel setup',
    57: 'Failed to modify channel name',
    58: 'Failed to modify video channel',
    59: 'Failed to modify record setup',
    60: 'Failed to modify decoder property',
    61: 'Failed to modify 232 COM setup',
    62: 'Failed to modify external input alarm setup',
    63: 'Failed to modify motion detection alarm setup',
    64: 'Failed to modify device time',
    65: 'Failed to modify preview parameter',
    66: 'Failed to modify auto maintenance setup',
    67: 'Failed to modify video matrix setup',
    68: 'Failed to modify privacy mask zone',
    69: 'Failed to modify video watermark setup',
    70: 'Failed to modify wireless network information',
    71: 'Failed to select wireless network device',
    72: 'Failed to modify the actively registration parameter setup.',
    73: 'Failed to modify camera property',
    74: 'Failed to modify IR alarm setup',
    75: 'Failed to modify audio alarm setup',
    76: 'Failed to modify storage position setup',
    77: 'The audio encode port has not been successfully initialized.',
    78: 'The data are too long.',
    79: 'The device does not support current operation.',
    80: 'Device resources is not sufficient.',
    81: 'The server has boot up',
    82: 'The server has not fully boot up',
    83: 'Input serial number is not correct.',
    84: 'Failed to get HDD information.',
    85: 'Failed to get connect session information.',
    86: 'The password you typed is incorrect. You have exceeded the maximum number of retries.',
    99: 'password expired',
    100: 'Password is not correct',
    101: 'The account does not exist',
    102: 'Time out for log in returned value.',
    103: 'The account has logged in',
    104: 'The account has been locked',
    105: 'The account has been in the block list',
    106: 'Resources are not sufficient. System is busy now.',
    107: 'Time out. Please check network and try again.',
    108: 'Network connection failed.',
    109: 'Successfully logged in the device but can not create video channel. Please check network connection.',
    110: 'exceed the max connect number',
    111: 'protocol 3 support',
    112: 'There is no USB or USB info error',
    113: 'Client-end IP address has no right to login',
    117: 'user or password error',
    118: 'cannot login because the device has not been init,please init the device and then login',
    119: 'Limited login, it could be IP limited, time limited or expiration limited',
    120: 'Error occurs when Render library open audio.',
    121: 'Error occurs when Render library close audio',
    122: 'Error occurs when Render library control volume',
    123: 'Error occurs when Render library set video parameter',
    124: 'Error occurs when Render library pause play',
    125: 'Render library snapshot error',
    126: 'Render library stepper error',
    127: 'Error occurs when Render library set frame rate.',
    128: 'Error occurs when Render lib setting show region',
    129: 'An error occurred when Render library getting current play time',
    140: 'Group name has been existed.',
    141: 'The group name does not exist.',
    142: 'The group right exceeds the right list!',
    143: 'The group can not be removed since there is user in it!',
    144: 'The user has used one of the group right. It can not be removed.',
    145: 'New group name has been existed',
    146: 'The user name has been existed',
    147: 'The account does not exist.',
    148: 'User right exceeds the group right.',
    149: 'Reserved account. It does not allow to be modified.',
    150: 'password is not correct',
    151: 'Password is invalid',
    152: 'account in use',
    300: 'Failed to get network card setup.',
    301: 'Failed to get wireless network information.',
    302: 'Failed to get wireless network device.',
    303: 'Failed to get actively registration parameter.',
    304: 'Failed to get camera property',
    305: 'Failed to get IR alarm setup',
    306: 'Failed to get audio alarm setup',
    307: 'Failed to get storage position',
    308: 'Failed to get mail setup.',
    309: 'Can not set right now.',
    310: 'The configuration setup data are illegal.',
    311: 'Failed to get DST setup',
    312: 'Failed to set DST',
    313: 'Failed to get video OSD setup.',
    314: 'Failed to set video OSD',
    315: 'Failed to get CDMA\GPRS configuration',
    316: 'Failed to set CDMA\GPRS configuration',
    317: 'Failed to get IP Filter configuration',
    318: 'Failed to set IP Filter configuration',
    319: 'Failed to get Talk Encode configuration',
    320: 'Failed to set Talk Encode configuration',
    321: 'Failed to get The length of the video package configuration',
    322: 'Failed to set The length of the video package configuration',
    323: 'Not support Network hard disk partition',
    324: 'Failed to get the register server information',
    325: 'Failed to control actively registration',
    326: 'Failed to disconnect actively registration',
    327: 'Failed to get mms configuration',
    328: 'Failed to set mms configuration',
    329: 'Failed to get SMS configuration',
    330: 'Failed to set SMS configuration',
    331: 'Failed to get activation of a wireless connection',
    332: 'Failed to set activation of a wireless connection',
    333: 'Failed to get the parameter of video output',
    334: 'Failed to set the configuration of video output',
    335: 'Failed to get osd overlay enabling',
    336: 'Failed to set OSD overlay enabling',
    337: 'Failed to set digital input configuration of front encoders',
    338: 'Failed to get TV adjust configuration',
    339: 'Failed to set TV adjust configuration',
    340: 'Failed to request to establish a connection',
    341: 'Failed to request to upload burn files',
    342: 'Failed to get capture configuration information',
    343: 'Failed to set capture configuration information',
    344: 'Failed to get download restrictions information',
    345: 'Failed to set download restrictions information',
    346: 'Failed to query serial port parameters',
    347: 'Failed to get the preset info',
    348: 'Failed to set the preset info',
    349: 'SDK log out the device abnormally',
    350: 'Failed to get vehicle configuration',
    351: 'Failed to set vehicle configuration',
    352: 'Failed to get ATM overlay configuration',
    353: 'Failed to set ATM overlay configuration',
    354: 'Failed to get ATM overlay ability',
    355: 'Failed to get decoder tour configuration',
    356: 'Failed to set decoder tour configuration',
    357: 'Failed to control decoder tour',
    358: 'Beyond the device supports for the largest number of user groups',
    359: 'Beyond the device supports for the largest number of users',
    368: 'Failed to get SIP configuration',
    369: 'Failed to set SIP configuration',
    370: 'Failed to get SIP capability',
    371: 'Failed to get "WIFI ap" configuration',
    372: 'Failed to set "WIFI ap" configuration',
    373: 'Failed to get decode policy',
    374: 'Failed to set decode policy',
    375: 'refuse talk',
    376: 'talk has opened by other client',
    377: 'resource conflict',
    378: 'unsupported encode type',
    379: 'no right',
    380: 'request failed',
    381: 'Failed to get device relative config',
    382: 'Failed to set device relative config',
    383: 'get data failed',
    384: 'MAC validate failed',
    385: 'Failed to get server instance',
    386: 'Generated json string is error',
    387: 'The responding json string is error',
    388: 'The protocol version is lower than current version',
    389: 'Hotspare disk operation failed. The capacity is low',
    390: 'Display source is used by other output',
    391: 'advanced users grab low-level user resource',
    392: 'net forbid',
    393: 'get MAC filter configuration error',
    394: 'set MAC filter configuration error',
    395: 'get IP/MAC filter configuration error',
    396: 'set IP/MAC filter configuration error',
    397: 'operation over time',
    398: 'senior validation failure',
    399: 'device ID is not exist',
    400: 'unsupport operation',
    401: 'proxy dll load error',
    402: 'proxy user parameter is not legal',
    403: 'handle invalid',
    404: 'login device error',
    405: 'start proxy server error',
    406: 'request speak failed',
    407: 'unsupport F6',
    408: 'CD is not ready',
    409: 'Directory does not exist',
    410: 'The device does not support the segmentation model',
    411: 'Open the window parameter is illegal',
    412: 'Open the window more than limit',
    413: "Request command with the current pattern don't match",
    414: 'Render Library to enable high-definition image internal adjustment strategy error',
    415: 'Upgrade equipment failure',
    416: "Can't find the target device",
    417: "Can't find the verify device",
    418: 'No cascade permissions',
    419: 'low priority',
    420: 'The remote device request timeout',
    421: 'Input source beyond maximum route restrictions',
    422: 'Failed to set log print',
    423: '"dwSize" is not initialized in input param',
    424: 'TV wall exceed limit',
    425: 'Fail to execute part of the process',
    426: 'Fail to transmit due to not supported by target',
    510: 'Access to the file failed',
    511: 'Device busy',
    512: 'Fail to change the password',
    513: 'Password strength is not enough',
    514: 'No corresponding setup',
    515: 'Failed to record audio',
    516: 'Failed to send out data',
    517: 'Abandoned port',
    518: 'Internal buffer is not sufficient',
    519: 'verify password when changing device IP',
    520: 'device not support the record',
    521: 'Device is in upgrading',
    522: 'Analyse Task Not Exist',
    523: 'Analyse Task Full',
    1010: 'Failed to serialize data',
    1011: 'Failed to deserialize data',
    1012: 'the wireless id is already existed',
    1013: 'the wireless id limited',
    1014: 'add the wireless id abnormaly',
    1015: 'encrypt data fail',
    1016: 'new password illegal',
    1017: 'device is already init',
    1018: 'security code check out fail',
    1019: 'security code out of time',
    1020: 'get passwd specification fail',
    1021: 'no authority of operation',
    1022: 'decrypt data fail',
    1023: '2D code check out fail',
    1024: 'invalid request',
    1025: 'pwd reset unable',
    1026: 'failed to display private data,such as rule box',
    1027: 'robot operate failed',
    1028: 'photosize exceeds limit',
    1029: 'userid invalid',
    1030: 'photo extract feature failed',
    1031: 'photo exist',
    1032: 'photo over flow',
    1033: 'channel has already been opened',
    1034: 'create socket error',
    1035: 'invalid channel num',
    1036: 'photo format error',
    1037: 'Internal error',
    1038: 'Get ID failed',
    1039: 'Import illegal',
    1040: 'SN error',
    1041: 'Cert common name illegal',
    1042: 'No root cert',
    1043: 'Cert revoked',
    1044: 'Cert invalid',
    1045: 'Cert error sign',
    1046: 'Counts upper limit',
    1047: 'Cert no exist',
    1048: "default search port can't use(5050,37810)",
    1049: 'target recognition server multi append stop',
    1050: 'target recognition server multi append error',
    1051: 'target recognition server group id exceed',
    1052: 'target recognition server group id not in register group',
    1053: 'target recognition server picture not found',
    1054: 'target recognition server generate group id failed',
    1055: 'target recognition server set config failed',
    1056: 'target recognition server file open failed',
    1057: 'target recognition server file read failed',
    1058: 'target recognition server file write failed',
    1059: 'target recognition server picture dpi error',
    1060: 'target recognition server picture px error',
    1061: 'target recognition server picture size error',
    1062: 'target recognition server database error',
    1063: 'target recognition server face max num',
    1064: 'target recognition server birthday format error',
    1065: 'target recognition server uid error',
    1066: 'target recognition server token error',
    1067: 'target recognition server begin num over run',
    1068: 'target recognition server abstract num zero',
    1069: 'target recognition server abstract init error',
    1070: 'target recognition server auto abstract state',
    1071: 'target recognition server abstract state',
    1072: 'target recognition server im ex state',
    1073: 'target recognition server pic write failed',
    1074: 'target recognition server group space exceed',
    1075: 'target recognition server group pic count exceed',
    1076: 'target recognition server group not found',
    1077: 'target recognition server find record error',
    1078: 'target recognition server delete person error',
    1079: 'target recognition server delete group error',
    1080: 'target recognition server name format error',
    1081: 'target recognition server file path not set',
    1082: 'device internal request timeout',
    1083: 'device keeps alive fail',
    1084: 'device network error',
    1085: 'device unknown error',
    1086: 'device not found com interface',
    1087: 'device not found com implement',
    1088: 'device not found client component',
    1089: 'device not found client com instance',
    1090: 'device creates com fail',
    1091: 'device gets com instance fail',
    1092: 'device can not accept bad request',
    1093: 'device does not accept repeat request when in progressing',
    1094: 'device limited resource',
    1095: 'device business timeout',
    1096: 'device accepts too many requests',
    1097: 'device not already and cannot accept request',
    1098: 'device searchs record timeout',
    1099: 'device checks search record time invalid',
    1100: 'device checks SSID invalid',
    1101: 'device checks channel or streamtype invalid',
    1102: 'device does not support stream packing format',
    1103: 'device does not support audio encoding format',
    1104: 'check request security failed, using local GUI reset password',
    1105: 'check request security failed, using Private APP or configtool reset password',
    1106: 'check request security failed, using Web reset password',
    1107: 'streamconvertor defect',
    1108: 'generate safe code failed',
    1109: 'get contact failed',
    1110: 'get QR code information failed of reset passwd',
    1111: "device uninitialized, can't reset",
    1112: 'unsupported contact mode',
    1113: 'server response time out',
    1114: 'had check AuthCode too much, forbid check',
    1115: '(virtual transcode)login remote device failed',
    1116: '(virtual transcode)no free virtual channel',
    1117: 'VK info decrypt failed',
    1118: 'VK info deserial failed',
    1119: 'SDK GDPR ability not enable',
    1120: 'access control fast check:no authority',
    1121: 'access control fast check:file does not exist',
    1122: 'access control fast check:fail to prepare file',
    1123: 'access control fast check:system is busy',
    1124: 'access control fast check:no password, and import is not allowed',
    1125: 'access control fast import:fail to send access control data',
    1126: 'access control fast import:system is busy',
    1127: 'access control fast import:packet data check failed',
    1128: 'access control fast import:illegal packet data',
    1129: 'access control fast import:fail to synchronization',
    1130: 'access control fast import:data base is full',
    1131: 'access control fast import:SD is full',
    1132: 'access control fast import:password error',
    1133: 'invalid param',
    1134: 'invalid password',
    1135: 'invalid finger print',
    1136: 'invalid face',
    1137: 'invalid card',
    1138: 'invalid user',
    1139: 'device get sub service fail',
    1140: 'device get method fail',
    1141: 'device get sub caps fail',
    1142: 'up to insert limit',
    1143: 'up tp max insert rate',
    1144: 'erase finger print data fail',
    1145: 'erase face data fail',
    1146: 'erase card data fail',
    1147: 'no record',
    1148: 'no more records',
    1149: 'record already exist',
    1150: 'exceed max finger print per user',
    1151: 'exceed max card per user',
    1152: 'exceed administrator limit',
    1153: 'device not support high level security login',
    1154: 'device only support high level security login',
    1155: 'current video channel is offline, play failed',
    1156: 'The format of the User ID is incorrect - should be all digital numbers',
    1157: 'The corresponding channel to this serial number could not be found',
    1158: 'The task queue for this channel is full',
    1159: 'Applying for new user information blocks failed',
    1160: "The maximum number of user's password exceeded",
    1161: 'Internal error when parsing protocol packages',
    1162: 'card num already exist',
    1163: 'finger print already exist',
    1164: 'open play group fail',
    1165: 'play handle already in play group',
    1166: 'query play group time fail',
    1167: 'set play group base channel fail',
    1168: 'set play group direction fail',
    1169: 'set play group speed fail',
    1170: 'add play handle to play group fail',
    1171: 'export aol log file:no auth',
    1172: 'export aol log file:no file',
    1173: 'export aol log file:prepare file fail',
    1174: 'export aol log file:device busy',
    1175: 'Empty license',
    1176: 'Unsupported mode',
    1177: 'Url and App are not match',
    1178: 'Read info failed',
    1179: 'Write failed',
    1180: 'No such App',
    1181: 'Verify failed',
    1182: 'License out of date',
    1183: 'upgrade program version too old',
    1184: 'secure transmit has been cut',
    1185: 'device not support secure transmit',
    1186: 'when main stream success, extra stream login fail',
    1187: 'extra stream closed by remote device',
    1188: 'Import facedb: Failed to send face database data',
    1189: 'Import facedb: The system is busy. There are import tasks',
    1190: 'Import facedb: Packet validation failed',
    1191: 'Import facedb: Invalid packet',
    1192: 'Import facedb:Upload failed',
    1193: 'Import facedb:No authority',
    1194: 'Import facedb:Abnormal file',
    1195: 'Import facedb: Synchronization failed, database could not be generated',
    1196: 'Import facedb: Database is full, unable to import',
    1197: 'Import facedb: Storage space is full, unable to import',
    1198: 'Import facedb: Incorrect password for importing compressed package',
    1199: 'Export facedb: No authority',
    1200: 'Export facedb: File does not exist',
    1201: 'Export facedb: File preparation failed',
    1202: 'Export facedb: System busy',
    1203: 'Export facedb: No password defined, export not allowed',
    1300: 'No face detected',
    1301: 'Multi face detected ¨C Can not extract eigenvalues',
    1302: 'Picture decoding error',
    1303: 'The picture quality is too low',
    1304: 'Not recommended ¨C Eigen style mismatched to the algorithm model',
    1305: 'Face eigenvalue already exist',
    1307: 'Face angle over thresholds',
    1308: 'Face radio exceeds range',
    1309: 'Face over exposed',
    1310: 'Face under exposed',
    1311: 'Face brightness imbalance',
    1312: 'Face lower confidence level',
    1313: 'Face low align score',
    1314: 'Fragmentary face detected',
    1315: 'Pupil distance in the photo is not enough',
    1316: 'Face download failed',
    1317: 'Working mode error',
    1318: 'Busy collecting',
    1319: 'Does not support this collection method',
    1320: 'Ordinary users do not support delivery',
    1321: 'The forced start-up of the refrigerator is invalid, and the opening times have been used up on the same day',
    1322: 'The delayed shutdown of the refrigerator is invalid, and the delay times have been reached on the same day',
    1323: 'CitizenID is already exist',
    1324: 'The face can be detected, but the feature value extraction fails (algorithm scene)',
    1325: 'The feature value extracted from the face photo is incorrect due to the inconsistency of face attributes such as masks, hats, sunglasses, etc.',
    1326: 'Incomplete face photo',
}




class Singleton(type):
    def __init__(self, *args, **kwargs):
        self.__instance = None
        super().__init__(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        if self.__instance is None:
            self.__instance = super(Singleton, self).__call__(*args, **kwargs)
        return self.__instance


class NetClient(metaclass=Singleton):
    """
    所有sdk接口都定义为该类的类方法
    all function in sdk which used define in this class
    """

    def __init__(self, *args, **kwargs):
        self._load_library()

    @classmethod
    def _load_library(cls):
        try:
            cls.sdk = load_library(netsdkdllpath)
            cls.config_sdk = load_library(configdllpath)
            cls.render_sdk = load_library(rendersdkdllpath)
            cls.infra_sdk = load_library(infrasdkdllpath)
            cls.image_alg = load_library(imagealgdllpath)
            cls.play_sdk = load_library(playsdkdllpath)
        except OSError as e:
            print('动态库加载失败')

    @classmethod
    def GetLastError(cls) -> int:
        """
        获取错误码;Return the function execution failure code
        """
        return cls.sdk.CLIENT_GetLastError() & 0x7fffffff

    @classmethod
    def GetLastErrorMessage(cls) -> str:
        """
        通过错误码获取错误信息;get the error message by error code
        """
        errcode = cls.GetLastError()
        if isinstance(errcode, int) is True:
            try:
                return error_code[errcode]
            except KeyError:
                return 'There is no such error code'
        else:
            return 'Unknown mistake'

    @classmethod
    def InitEx(cls, call_back: fDisConnect = None, user_data: C_LDWORD = 0, init_param: NETSDK_INIT_PARAM = NETSDK_INIT_PARAM()) -> int:
        """
        初始化接口，之前须先保证该接口调用成功;SDK initialization,called before using the SDK
        :param call_back: 回调函数;call back
        :param user_data:用户数据;user data
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        init_param = pointer(init_param)
        result = cls.sdk.CLIENT_InitEx(call_back, user_data, init_param)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def Cleanup(cls):
        """
        SDK退出清理,Release sdk source
        """
        cls.sdk.CLIENT_Cleanup()

    @classmethod
    def LoginEx2(cls, ip: str, port: int, username: str, password: str, spec_cap: EM_LOGIN_SPAC_CAP_TYPE = EM_LOGIN_SPAC_CAP_TYPE.TCP, cap_param: c_void_p = None) -> tuple:
        """
        """
        ip = c_char_p(ip.encode())
        port = c_ushort(int(port))
        username = c_char_p(username.encode())
        password = c_char_p(password.encode())
        spec_cap = c_int(spec_cap)
        cap_param = byref(cap_param) if cap_param is not None else None
        error = c_int(0)
        error_message = ''
        device_info = NET_DEVICEINFO_Ex()
        cls.sdk.CLIENT_LoginEx2.restype = C_LLONG
        login_id = cls.sdk.CLIENT_LoginEx2(ip, port, username, password,
                                           spec_cap, cap_param, byref(device_info), byref(error))
        login_error = {
            1: 'username or passwd invalid',
            2: 'user not exist',
            3: 'timeout',
            4: 'repeat login',
            5: 'account has been locked',
            6: 'the account has been blocklisted',
            7: 'system busy, insufficient resources',
            8: 'sub socket connect fail',
            9: 'main socket connect fail',
            10: 'exceed max num of connections',
            11: 'device only support third protocol login',
            12: 'device not insert U shield or U shiled info invalid',
            13: 'client ip address is not permit to login',
            18: 'device does not been initialized,so cannot be login',
            19: 'limited login',
            20: 'device only support high level security login'
        }
        if login_id == 0:
            try:
                error_message = login_error[error.value]
            except KeyError:
                error_message = 'There is no such error code'
            print(error_message)
        return login_id, device_info, error_message

    @classmethod
    def LoginWithHighLevelSecurity(cls, stuInParam: NET_IN_LOGIN_WITH_HIGHLEVEL_SECURITY, stuOutParam: NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY) -> tuple:
        """
        高安全级别登陆;login device with high level security
        :param stuInParam:传入参数结构体;in parameter structure
        :param stuOutParam:传出参数结构体;out parameter structure
        :return:login_id:成功返回登录句柄，失败返回0，登录成功后设备信息保存在NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY的stuDeviceInfo;
                         secssed：login id,failed：0，if login succeed,device info in stuDeviceInfo of NET_OUT_LOGIN_WITH_HIGHLEVEL_SECURITY
                device_info:输出的设备信息;device information，for output parmaeter
                error_message:登录接口的错误信息；error message of login
        """
        cls.sdk.CLIENT_LoginWithHighLevelSecurity.restype = C_LLONG
        login_id = cls.sdk.CLIENT_LoginWithHighLevelSecurity(byref(stuInParam), byref(stuOutParam))
        login_error = {
            1: '账号或密码错误',
            2: '用户名不存在',
            3: '登录超时',
            4: '重复登录',
            5: '帐号被锁定',
            6: '帐号被列入禁止名单',
            7: '系统忙,资源不足',
            8: '子连接失败',
            9: '主连接失败',
            10: '超过最大连接数',
            11: '只支持3代协议',
            12: '设备未插入U盾或U盾信息错误',
            13: '客户端IP地址没有登录权限',
            18: '设备账号未初始化，无法登陆'
        }
        error_message = ''
        device_info = NET_DEVICEINFO_Ex()
        if login_id == 0:
            try:
                error_message = login_error[stuOutParam.nError]
            except KeyError:
                error_message = 'There is no such error code'
            print(error_message)
        else:
            device_info = stuOutParam.stuDeviceInfo
        return login_id, device_info, error_message

    @classmethod
    def SetAutoReconnect(cls, call_back: fHaveReConnect, user_data: C_LDWORD = None):
        """
        设置断线重连成功回调函数,设置后SDK内部断线自动重连;Set re-connection callback function after disconnection. Internal SDK  auto connect again after disconnection
        :param call_back:重连成功回调函数;Reconnect callback
        :param user_data:自定义用户数据;User data
        """
        user_data = byref(c_uint(user_data)) if user_data is not None else None
        cls.sdk.CLIENT_SetAutoReconnect(call_back, user_data)

    @classmethod
    def Logout(cls, login_id: int) -> int:
        """
        向设备注销;Log out the device
        :param login_id:登陆ID,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        login_id = C_LLONG(login_id)
        result = cls.sdk.CLIENT_Logout(login_id)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def LogOpen(cls, log_info: LOG_SET_PRINT_INFO) -> int:
        """
        打开日志功能;open log function
        :param log_info:日志相关设置参数; param of log setting
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        log_info = pointer(log_info)
        result = cls.sdk.CLIENT_LogOpen(log_info)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def LogClose(cls) -> int:
        """
        关闭日志功能;close log function
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        result = cls.sdk.CLIENT_LogClose()
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RealPlayEx(cls, login_id: int, channel: int, hwnd: int, play_type = SDK_RealPlayType.Realplay) -> C_LLONG:
        """
        开始实时预览;Begin real-time monitor
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel:通道号;real time monitor channel NO.(from 0).
        :param hwnd:窗口句柄;display window handle.
        :param play_type:主码流类型;realplay type
        :return:realplay_id:失败返回0，成功返回大于0的值;failed return 0, successful return the real time monitorID(real time monitor handle),as parameter of related function.
        """

        login_id = C_LLONG(login_id)
        channel = c_int(channel)
        hwnd = c_long(hwnd)
        play_type = c_int(play_type)
        cls.sdk.CLIENT_RealPlayEx.restype = C_LLONG
        realplay_id = cls.sdk.CLIENT_RealPlayEx(login_id, channel, hwnd, play_type)
        if realplay_id == 0:
            print(cls.GetLastErrorMessage())
        return realplay_id

    @classmethod
    def RealPlayByDataType(cls, lLoginID: int, pstInParam: NET_IN_REALPLAY_BY_DATA_TYPE, pstOutParam: NET_OUT_REALPLAY_BY_DATA_TYPE, dwWaitTime: int = 5000) -> C_LLONG:
        """
        指定回调数据类型 实施预览(预览), 数据回调函数 cbRealData 中得到的码流类型为 emDataType 所指定的类型;RealPlay By Stream Data Type
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:输入参数;input param
        :param pstOutParam:输出参数;output param
        :param dwWaitTime:等待时间;Wait time
        :return:realplay_id:失败返回0，成功返回大于0的值;failed return 0, successful return the real time monitorID(real time monitor handle),as parameter of related function.
        """
        login_id = C_LLONG(lLoginID)
        cls.sdk.CLIENT_RealPlayByDataType.restype = C_LLONG
        realplay_id = cls.sdk.CLIENT_RealPlayByDataType(login_id, byref(pstInParam), byref(pstOutParam), dwWaitTime)
        if realplay_id == 0:
            print(cls.GetLastErrorMessage())
        return realplay_id

    @classmethod
    def PlayBackByDataType(cls, lLoginID: int, pstInParam: NET_IN_PLAYBACK_BY_DATA_TYPE, pstOutParam: NET_OUT_PLAYBACK_BY_DATA_TYPE, dwWaitTime: int = 5000) -> C_LLONG:
        """
        指定回调数据格式 开始回放,数据回调函数 fDownLoadDataCallBack中得到的码流类型为 emDataType 所指定的类型;PlayBack By Stream Data Type
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:输入参数;input param
        :param pstOutParam:输出参数;output param
        :param dwWaitTime:等待时间;Wait time
        :return:playback_id:失败返回0，成功返回大于0的值;failed return 0, successful return the playback time monitorID(playback time monitor handle),as parameter of related function.
        """
        login_id = C_LLONG(lLoginID)
        cls.sdk.CLIENT_PlayBackByDataType.restype = C_LLONG
        playback_id = cls.sdk.CLIENT_PlayBackByDataType(login_id, byref(pstInParam), byref(pstOutParam), dwWaitTime)
        if playback_id == 0:
            print(cls.GetLastErrorMessage())
        return playback_id

    @classmethod
    def DownloadByDataType(cls, lLoginID: int, pstInParam: NET_IN_DOWNLOAD_BY_DATA_TYPE, pstOutParam: NET_OUT_DOWNLOAD_BY_DATA_TYPE, dwWaitTime: int = 5000) -> C_LLONG:
        """
        指定码流类型 开始下载, 下载得到的文件和数据回调函数 fDownLoadDataCallBack 中得到的码流类型均为 emDataType 所指定的类型; Specify the stream type to start downloading
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:输入参数;input param
        :param pstOutParam:输出参数;output param
        :param dwWaitTime:等待时间;Wait time
        :return:download_id:失败返回0，成功返回大于0的值;failed return 0, successful return download handle ID.
        """
        login_id = C_LLONG(lLoginID)
        cls.sdk.CLIENT_DownloadByDataType.restype = C_LLONG
        download_id = cls.sdk.CLIENT_DownloadByDataType(login_id, byref(pstInParam), byref(pstOutParam), dwWaitTime)
        if download_id == 0:
            print(cls.GetLastErrorMessage())
        return download_id

    @classmethod
    def SetRealDataCallBackEx2(cls, realplay_id: int, cbRealData: fRealDataCallBackEx2, dwUser: C_LDWORD, dwFlag: EM_REALDATA_FLAG) -> bool:
        """
        开始实时预览;Begin real-time monitor
        :param realplay_id:预览ID,RealPlayEx返回值;monitor handle,RealPlayEx returns value
        :param cbRealData:回调函数;callback function
        :param dwUser:用户数据;user data
        :param dwFlag:回调数据类型;real data type
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        realplay_id = C_LLONG(realplay_id)
        dwFlag = C_DWORD(dwFlag)
        result = cls.sdk.CLIENT_SetRealDataCallBackEx2(realplay_id, cbRealData, dwUser, dwFlag)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopRealPlayEx(cls, realplay_id: int) -> int:
        """
        停止实时预览;stop real-time preview
        :param realplay_id:预览ID,RealPlayEx返回值;monitor handle,RealPlayEx returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        realplay_id = C_LLONG(realplay_id)
        result = cls.sdk.CLIENT_StopRealPlayEx(realplay_id)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartSearchDevicesEx(cls, pInBuf: NET_IN_STARTSERACH_DEVICE, pOutBuf: NET_OUT_STARTSERACH_DEVICE) -> C_LLONG:
        """
        异步搜索设备;asynchronism search device
        :param pInBuf:输入参数;input param
        :param pOutBuf:输出参数;output param
        :return:搜索句柄;search handle
        """
        cls.sdk.CLIENT_StartSearchDevicesEx.restype = C_LLONG
        result = cls.sdk.CLIENT_StartSearchDevicesEx(byref(pInBuf), byref(pOutBuf))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SearchDevicesByIPs(cls, pIpSearchInfo: DEVICE_IP_SEARCH_INFO, cbSearchDevices: fSearchDevicesCB, dwUserData: C_LDWORD, szLocalIp: c_char_p = None, dwWaitTime: C_DWORD = 5000) -> c_int:
        """
        跨网段搜索设备IP;search device ip cross VLAN
        :param pIpSearchInfo:待搜索的IP信息,ENGLISH_LANG:IP info of
        :param cbSearchDevices:回调函数,ENGLISH_LANG:Search devices call back
        :param dwUserData:用户数据,ENGLISH_LANG:User data
        :param szLocalIp:本地IP,ENGLISH_LANG:Local IP
        :param dwWaitTime:等待时间,ENGLISH_LANG:Wait time
        :return:1:搜索成功,0:搜索失败;1:search device success,0:search device failed
        """
        szLocalIp = c_char_p(szLocalIp)
        dwUserData = C_LDWORD(dwUserData)
        dwWaitTime = C_DWORD(dwWaitTime)
        result = cls.sdk.CLIENT_SearchDevicesByIPs(byref(pIpSearchInfo), cbSearchDevices, dwUserData, szLocalIp, dwWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopSearchDevices(cls, lSearchHandle: C_LLONG) -> c_int:
        """
        异步停止搜索设备;stop asynchronism search IPC, NVS and etc in LAN
        :param lSearchHandle:搜索句柄;search handle
        :return:1:停止搜索成功,0:停止搜索失败;1:stop search device success,0:stop search device failed
        """
        lSearchHandle = C_LLONG(lSearchHandle)
        result = cls.sdk.CLIENT_StopSearchDevices(lSearchHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def InitDevAccount(cls, pInitAccountIn: NET_IN_INIT_DEVICE_ACCOUNT, pInitAccountOut: NET_OUT_INIT_DEVICE_ACCOUNT, dwWaitTime: int = 5000, szLocalIp: c_char_p = None) -> c_int:
        """
            初始化设备账户;init account
            :param pInitAccountIn:输入参数结构体NET_IN_INIT_DEVICE_ACCOUNT;input param,corresponding to NET_IN_INIT_DEVICE_ACCOUNT
            :param pInitAccountOut:输出参数结构体NET_OUT_INIT_DEVICE_ACCOUNT;output param,corresponding to NET_OUT_INIT_DEVICE_ACCOUNT
            :return:1:初始化设备账户成功,0:初始化设备账户失败;1:Init device account success,0:Init device account failed
        """
        szLocalIp = c_char_p(szLocalIp)
        result = cls.sdk.CLIENT_InitDevAccount(byref(pInitAccountIn), byref(pInitAccountOut), dwWaitTime, szLocalIp)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RealLoadPictureEx(cls, lLoginID: C_LLONG, nChannelID: c_int, dwAlarmType: c_ulong, bNeedPicFile: c_int, cbAnalyzerData: fAnalyzerDataCallBack, dwUser: C_LDWORD = 0, reserved: c_void_p = None) -> C_LLONG:
        """
        实时上传智能分析数据图片(扩展接口,bNeedPicFile表示是否订阅图片文件); real load picture of intelligent analysis(expand interface: 'bNeedPicFile == true' instruct load picture file, 'bNeedPicFile == false' instruct not load picture file )
        :param lLoginID:登陆ID; login returns value
        :param nChannelID:通道号; channel id
        :param dwAlarmType:事件类型,参考EM_EVENT_IVS_TYPE; event type see EM_EVENT_IVS_TYPE
        :param bNeedPicFile:是否订阅图片文件; subscribe image file or not,ture-yes,return intelligent image info during callback function,false not return intelligent image info during callback function
        :param cbAnalyzerData:事件回调函数; intelligent data analysis callback
        :param dwUser:用户数据; user data
        :param reserved:保留参数; reserved
        :return:订阅句柄;Handle
        """
        lLoginID = C_LLONG(lLoginID)
        nChannelID = c_int(nChannelID)
        dwAlarmType = c_ulong(dwAlarmType)
        bNeedPicFile = c_int(bNeedPicFile)
        dwUser = C_LDWORD(dwUser)
        reserved = c_void_p(reserved)
        cls.sdk.CLIENT_RealLoadPictureEx.restype = C_LLONG
        event_id = cls.sdk.CLIENT_RealLoadPictureEx(lLoginID, nChannelID, dwAlarmType, bNeedPicFile, cbAnalyzerData,
                                                    dwUser, reserved)
        if not event_id:
            print(cls.GetLastErrorMessage())
        return event_id

    @classmethod
    def StopLoadPic(cls, lAnalyzerHandle: C_LLONG) -> c_int:
        """
        停止上传智能分析数据－图片;stop asynchronism search IPC, NVS and etc in LAN
        :param lAnalyzerHandle:订阅句柄,RealLoadPictureEx接口返回值;handle,the value is returned by RealLoadPictureEx
        :return:1:停止订阅成功,0:停止订阅失败;1:StopLoadPic success,0:StopLoadPic failed
        """
        lAnalyzerHandle = C_LLONG(lAnalyzerHandle)
        result = cls.sdk.CLIENT_StopLoadPic(lAnalyzerHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetDeviceMode(cls, login_id: int, emType: int, value: c_void_p) -> c_int:
        """
        设置语音对讲模式,客户端方式还是服务器方式(pValue内存由用户申请释放，大小参照EM_USEDEV_MODE对应的结构体); Set audio talk mode(client-end mode or server mode), user malloc pValue's memory,please refer to the corresponding structure of EM_USEDEV_MODE
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param emType:工作模式类型; user work mode
        :param value:emType对应的结构体; support these emType
        :return:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        emType = c_int(emType)
        p_value = pointer(value)
        result = cls.sdk.CLIENT_SetDeviceMode(login_id, emType, p_value)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryRecordFile(cls, login_id: int, channel_id: int, recordfile_type: int, start_time: NET_TIME, end_time: NET_TIME, card_id: str, wait_time: int, is_querybytime: bool) -> tuple:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param recordfile_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param start_time:起始时间; start time
        :param end_time:结束时间; end time
        :param card_id:卡号; card id
        :param wait_time:超时时间; wait timr
        :param is_querybytime:是否是按时间查询; query by time or not
        :return:result:成功：1，失败：0；succeed：1，failed：0
                file_count:返回文件个数; the file count of query
                recordfile_infos:文件信息; record file infos
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        recordfile_type = c_int(recordfile_type)
        recordfile_infos = NET_RECORDFILE_INFO * 5000
        p_recordfile_infos = recordfile_infos()
        maxlen = sizeof(NET_RECORDFILE_INFO) * 5000
        maxlen = c_int(maxlen)
        file_count = c_int(0)
        is_querybytime = c_bool(is_querybytime)

        result = cls.sdk.CLIENT_QueryRecordFile(login_id, channel_id, recordfile_type, byref(start_time), byref(end_time),
                                                     card_id, p_recordfile_infos, maxlen, byref(file_count), wait_time, is_querybytime)
        if not result:
            print(cls.GetLastErrorMessage())
        else:
            file_count = file_count.value
            file_count = 5000 if file_count > 5000 else file_count
            recordfile_infos = p_recordfile_infos
        return result, file_count, recordfile_infos

    @classmethod
    def PlayBackByTimeEx(cls, login_id: int, channel_id: int, start_time: NET_TIME, end_time: NET_TIME, hwnd: C_LONG, callback_timedownloadpos: fDownLoadPosCallBack, time_UserData: C_LDWORD, callback_timedownloaddata: fDataCallBack, data_UserData: C_LDWORD) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param in_param:输入参数结构体NET_IN_PLAY_BACK_BY_TIME_INFO; input param,corresponding to NET_IN_PLAY_BACK_BY_TIME_INFO
        :param out_param:输出参数结构体NET_OUT_PLAY_BACK_BY_TIME_INFO; output param,corresponding to NET_OUT_PLAY_BACK_BY_TIME_INFO
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return 0
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        hwnd = C_LONG(hwnd)
        cls.sdk.CLIENT_PlayBackByTimeEx.restype = C_LLONG
        result = cls.sdk.CLIENT_PlayBackByTimeEx(login_id, channel_id, byref(start_time), byref(end_time), hwnd,
                                                 callback_timedownloadpos, time_UserData,
                                                 callback_timedownloaddata, data_UserData)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PlayBackByTimeEx2(cls, login_id: int, channel_id: int, in_param: NET_IN_PLAY_BACK_BY_TIME_INFO, out_param: NET_OUT_PLAY_BACK_BY_TIME_INFO) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param in_param:输入参数结构体NET_IN_PLAY_BACK_BY_TIME_INFO; input param,corresponding to NET_IN_PLAY_BACK_BY_TIME_INFO
        :param out_param:输出参数结构体NET_OUT_PLAY_BACK_BY_TIME_INFO; output param,corresponding to NET_OUT_PLAY_BACK_BY_TIME_INFO
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return 0
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        in_param = byref(in_param)
        out_param = byref(out_param)
        cls.sdk.CLIENT_PlayBackByTimeEx2.restype = C_LLONG
        result = cls.sdk.CLIENT_PlayBackByTimeEx2(login_id, channel_id, in_param, out_param)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopPlayBack(cls, playback_id: int) -> int:
        """
        停止回放; stop palyback
        :param playback_id:回放句柄, PlayBackByTimeEx2的返回值； palyback handle，PlayBackByTimeEx2's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if playback_id == 0:
            return
        playback_id = C_LLONG(playback_id)
        result = cls.sdk.CLIENT_StopPlayBack(playback_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PausePlayBack(cls, playback_id: int, is_pause: bool) -> int:
        """
        查询时间段内的所有录像文件; Search all recorded file sin the specified periods
        :param playback_id:回放句柄, PlayBackByTimeEx2的返回值； palyback handle，PlayBackByTimeEx2's returns value
        :param is_pause:操作动作，暂停还是继续; opreate type， pause or continue
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if playback_id == 0:
            return 0
        playback_id = C_LLONG(playback_id)
        is_pause = c_int(is_pause)
        result = cls.sdk.CLIENT_PausePlayBack(playback_id, is_pause)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DownloadByTimeEx(cls, login_id: int, channel_id: int, recordfile_type: int, start_time: NET_TIME, end_time: NET_TIME, save_filename: str, callback_timedownloadpos: fTimeDownLoadPosCallBack, time_UserData: C_LDWORD, callback_timedownloaddata: fDataCallBack, data_UserData: C_LDWORD, pReserved: int = 0) -> int:
        """
        通过时间下载录像--扩展; Through the time to download the video - extension
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param channel_id:查询通道号; user work mode
        :param recordfile_type:查询类型，参考EM_QUERY_RECORD_TYPE; type of record file,see EM_QUERY_RECORD_TYPE
        :param start_time:起始时间; start time
        :param end_time:结束时间; end time
        :param save_filename:保存录像的文件名; save file name
        :param callback_timedownloadpos:下载的时间回调; download by time's pos callback
        :param time_UserData:用户数据; callback_timedownloadpos's user data
        :param callback_timedownloaddata:下载的数据回调; video data's callback
        :param data_UserData:用户数据; callback_timedownloaddata's user data
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = c_int(channel_id)
        save_filename = c_char_p(save_filename.encode('gbk'))
        pReserved = pointer(c_int(pReserved))
        cls.sdk.CLIENT_DownloadByTimeEx.restype = C_LLONG
        result = cls.sdk.CLIENT_DownloadByTimeEx(login_id, channel_id, recordfile_type,
                                                 byref(start_time), byref(end_time), save_filename,
                                                 callback_timedownloadpos, time_UserData,
                                                 callback_timedownloaddata, data_UserData, pReserved)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopDownload(cls, download_id: int) -> int:
        """
        停止录像下载;  Stop record download
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        result = cls.sdk.CLIENT_StopDownload(download_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FastPlayBack(cls, download_id: int) -> int:
        """
        快进录像回放;  Fast forward video playback
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        result = cls.sdk.CLIENT_FastPlayBack(download_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SlowPlayBack(cls, download_id: int) -> int:
        """
        慢进录像回放;  Slow forward video playback
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        result = cls.sdk.CLIENT_SlowPlayBack(download_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def NormalPlayBack(cls, download_id: int) -> int:
        """
        恢复正常回放速度;  Restore normal playback speed
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        result = cls.sdk.CLIENT_NormalPlayBack(download_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PlayBackControlDirection(cls, download_id: int, backard: bool) -> int:
        """
        控制播放方向--正放或者倒放;  Control the playback direction - forward or backward
        :param download_id:下载句柄, DownloadByTimeEx的返回值； download handle，DownloadByTimeEx's returns value
        :param backard: false 正放,true 倒放
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if download_id == 0:
            return
        download_id = C_LLONG(download_id)
        backard = c_bool(backard)
        result = cls.sdk.CLIENT_PlayBackControlDirection(download_id, backard)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDevConfig(cls, login_id: C_LLONG, cfg_type: C_DWORD, channel_id: C_LONG, out_buffer: C_LLONG, outbuffer_size: C_DWORD, wait_time: int = 5000) -> int:
        """
        查询配置信息； Search configuration information
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param cfg_type:查询类型，参考 EM_DEV_CFG_TYPE; type,see EM_DEV_CFG_TYPE
        :param channel_id:查询通道号; user work mode
        :param out_buffer:获取的结构体数据; struct data of output
        :param outbuffer_size:out_buffer数据长度; size of out_buffer
        :param wait_time:超时时间; wait time
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = C_LONG(channel_id)
        out_buffer = pointer(out_buffer)
        outbuffer_size = C_DWORD(outbuffer_size)
        bytes_returned = c_uint(0)
        result = cls.sdk.CLIENT_GetDevConfig(login_id, cfg_type, channel_id, out_buffer, outbuffer_size, byref(bytes_returned), wait_time)
        if not result:
            print(cls.GetLastErrorMessage())
        if outbuffer_size.value != bytes_returned.value:
            print('返回结果出错(Return value is wrong!)')
            result = 0
        return result

    @classmethod
    def SetDevConfig(cls, login_id: C_LLONG, cfg_type: C_DWORD, channel_id: C_LONG, in_buffer: C_LLONG, inbuffer_size: C_DWORD, wait_time: int = 5000) -> int:
        """
        设置配置信息; Set configuration information
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param cfg_type:查询类型，参考EM_DEV_CFG_TYPE; type,see EM_DEV_CFG_TYPE
        :param channel_id:查询通道号; user work mode
        :param in_buffer:传入的结构体数据; struct data of input
        :param inbuffer_size:in_buffer数据长度; size of in_buffer
        :param wait_time:超时时间; wait time
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        channel_id = C_LONG(channel_id)
        in_buffer = pointer(in_buffer)
        inbuffer_size = C_DWORD(inbuffer_size)
        result = cls.sdk.CLIENT_SetDevConfig(login_id, cfg_type, channel_id, in_buffer, inbuffer_size, wait_time)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RebootDev(cls, login_id: int) -> int:
        """
        重启设备;  Reboot device
        :param login_id:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        if login_id == 0:
            return
        login_id = C_LLONG(login_id)
        result = cls.sdk.CLIENT_RebootDev(login_id)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetSnapRevCallBack(cls, OnSnapRevMessage: fSnapRev, dwUser: C_LDWORD) -> None:
        """
        设置抓图回调函数;Set snapshot callback function
        :param OnSnapRevMessage:抓图回调;snap receive message
        :param dwUser:用户数据；user data
        :return:None
        """
        dwUser = C_LDWORD(dwUser)
        cls.sdk.CLIENT_SetSnapRevCallBack(OnSnapRevMessage, dwUser)

    @classmethod
    def SnapPictureEx(cls, lLoginID: C_LLONG, par: SNAP_PARAMS, reserved = 0) -> c_int:
        """
        抓图请求扩展接口;Snapshot request--extensive
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param par:抓图参数结构体;Snapshot parameter structure
        :param reserved:保留字段；reserved
        :return:空；None
        """
        lLoginID = C_LLONG(lLoginID)
        par = pointer(par)
        reserved = pointer(c_int(reserved))
        result = cls.sdk.CLIENT_SnapPictureEx(lLoginID, par, reserved)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartListenEx(cls, lLoginID: C_LLONG) -> c_int:
        """
        向设备订阅报警--扩展;subscribe alarm---extensive
        :param lLoginID:登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_StartListenEx(lLoginID)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetDVRMessCallBackEx1(cls, cbMessage: fMessCallBackEx1, dwUser: C_LDWORD) -> None:
        """
        设置报警回调函数;Set alarm callback function
        :param cbMessage:消息回调函数原形(pBuf内存由SDK内部申请释放); Alarm message callback function original shape
        :param dwUser:用户数据；user data
        :return:空；None
        """
        dwUser = C_LDWORD(dwUser)
        cls.sdk.CLIENT_SetDVRMessCallBackEx1(cbMessage, dwUser)

    @classmethod
    def StopListen(cls, lLoginID: C_LLONG) -> c_int:
        """
        停止订阅报警;Stop subscribe alarm
        :param lLoginID: 登陆句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_StopListen(lLoginID)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RenderPrivateData(cls, realplay_id: C_LLONG, bTrue: bool) -> c_int:
        """
        显示私有数据，例如规则框，规则框报警，移动侦测等;Stop subscribe alarm
        :param realplay_id:预览ID,RealPlayEx返回值;monitor handle,RealPlayEx returns value
        :param lLoginID: 播放句柄,LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :return:1:成功，0：失败；1：success,0:failed
        """
        realplay_id = C_LLONG(realplay_id)
        bTrue = c_int(bTrue)
        result = cls.sdk.CLIENT_RenderPrivateData(realplay_id, bTrue)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetFreePort(cls) -> tuple:
        """
        Get free port. Range in 101~511
        :return:result: 1：success,0:failed
                port: Get free Port number
        """
        port = c_int()
        result = cls.play_sdk.PLAY_GetFreePort(byref(port))
        if not result:
            print('PLAY_GetFreePort error!')
        return result, port

    @classmethod
    def OpenStream(cls, port: c_int) -> bool:
        """
        Open stream interface (Just the same as open a file)
        :param port: Port number,GetFreePort's returns value
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_OpenStream(port, None, 0, 900*1024)
        if not result:
            print('PLAY_OpenStream error!')
        return result

    @classmethod
    def SetDecCallBack(cls, port: c_int, decoding_callback: fDecCBFun) -> bool:
        """
        Open stream interface (Just the same as open a file)
        :param port: Port number,GetFreePort's returns value
        :param decoding_callback: decoding call function indicator, cannot be NULL. Call function parameter definitions are as follows.
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_SetDecCallBack(port, decoding_callback)
        if not result:
            print('PLAY_SetDecCallBack error!')
        return result

    @classmethod
    def InputData(cls, port: c_int, pBuf: POINTER(c_byte), size: c_uint) -> bool:
        """
        Input the stream data you get from the card. Enable stream and Then call PLAY_Play to input data
        :param port: Port number,GetFreePort's returns value
        :param pBuf: Buffer address
        :param nSize: Buffer size
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_InputData(port, pBuf, size)
        if not result:
            print('PLAY_InputData error!')
        return result

    @classmethod
    def Play(cls, port: c_int, hwnd: int) -> bool:
        """
        Start play. If it is playing, then return current play status to normal speed
        :param port: Port number,GetFreePort's returns value
        :param hwnd: Play window handle
        :return:result: 1：success,0:failed
        """
        hwnd = C_LONG(hwnd)
        result = cls.play_sdk.PLAY_Play(port, hwnd)
        if not result:
            print('PLAY_Play error!')
        return result

    @classmethod
    def ReleasePort(cls, port: c_int) -> bool:
        """
        Release the port got with PLAY_GetFreePort
        :param port: Port number,GetFreePort's returns value
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_ReleasePort(port)
        if not result:
            print('PLAY_ReleasePort error!')
        return result

    @classmethod
    def CloseStream(cls, port: c_int) -> bool:
        """
        Close stream
        :param port: Port number,GetFreePort's returns value
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_CloseStream(port)
        if not result:
            print('PLAY_CloseStream error!')
        return result

    @classmethod
    def Stop(cls, port: c_int) -> bool:
        """
        Stop Play
        :param port: Port number,GetFreePort's returns value
        :return:result: 1：success,0:failed
        """
        result = cls.play_sdk.PLAY_Stop(port)
        if not result:
            print('PLAY_Stop error!')
        return result

    @classmethod
    def QueryDevInfo(cls, lLoginID: int, nQueryType: int, pInBuf: c_void_p, pOutBuf: c_void_p, pReserved: c_void_p = None, nWaitTime: int = 1000) -> int:
        """
        查询设备信息(pInBuf, pOutBuf内存由用户申请释放,根据nQueryType对应的类型找到相应的结构体，进而确定申请内存大小); search device info,user malloc memory of pInBuf and pOutBuf,please refer to nQueryType to ensure structure,then ensure memory size
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param nQueryType: 查询类型,其值为SDK_enum.py的EM_QUERY_DEV_INFO_TYPE；query type, refer to EM_QUERY_DEV_INFO_TYPE in SDK.Enum.py
        :param pInBuf:结构体输入参数;input param
        :param pOutBuf:结构体输出参数;output param
        :param pReserved:保留字段;Reserved
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        pReserved = c_void_p(pReserved)
        result = cls.sdk.CLIENT_QueryDevInfo(lLoginID, nQueryType, byref(pInBuf), byref(pOutBuf), pReserved, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachVideoStatSummary(cls, lLoginID: int, pInParam: NET_IN_ATTACH_VIDEOSTAT_SUM, pOutParam: NET_OUT_ATTACH_VIDEOSTAT_SUM, nWaitTime: int) -> C_LLONG:
        """
        订阅视频统计摘要信息;subscribe video statistical summary
        :param pInBuf:输入参数;input param
        :param pOutBuf:输出参数;output param
        :return:订阅句柄;attach handle
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_AttachVideoStatSummary.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachVideoStatSummary(lLoginID,byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachVideoStatSummary(cls, lAttachHandle: int) -> bool:
        """
        取消订阅视频统计摘要信息;unsubscribe video statistical summary
        :param lAttachHandle:订阅句柄，AttachVideoStatSummary接口返回值；Attach handle,return value of AttachVideoStatSummary
        :return:1:成功,0:失败;1:success,0:failed
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachVideoStatSummary(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindGroupInfo(cls, lLoginID: int, pstInParam: NET_IN_FIND_GROUP_INFO, pstOutParam: NET_OUT_FIND_GROUP_INFO, nWaitTime: int = 1000) -> int:
        """
        查询目标识别人员组信息,pstInParam与pstOutParam内存由用户申请释放； search target recognition staff group info ,user malloc and free (pstInParam's and pstOutParam's) memory
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:结构体输入参数;input param
        :param pstOutParam:结构体输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_FindGroupInfo(lLoginID, byref(pstInParam), byref(pstOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateFaceRecognitionGroup(cls, lLoginID: int, pstInParam: NET_IN_OPERATE_FACERECONGNITION_GROUP, pstOutParam: NET_OUT_OPERATE_FACERECONGNITION_GROUP, nWaitTime: int = 1000) -> int:
        """
        目标识别人员组操作（包括添加,修改和删除）,pstInParam与pstOutParam内存由用户申请释放； target recognition staff group operation, including add, modify and delete, ,user malloc and free (pstInParam's and pstOutParam's) memory
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:结构体输入参数;input param
        :param pstOutParam:结构体输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateFaceRecognitionGroup(lLoginID, byref(pstInParam), byref(pstOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateFaceRecognitionDB(cls, lLoginID: int, pstInParam: NET_IN_OPERATE_FACERECONGNITIONDB, pstOutParam: NET_OUT_OPERATE_FACERECONGNITIONDB, nWaitTime: int = 1000) -> int:
        """
        目标识别数据库信息操作（包括添加,修改和删除）,pstInParam与pstOutParam内存由用户申请释放； target recognition database info operation, including add and delete, ,user malloc and free (pstInParam's and pstOutParam's) memory
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam:结构体输入参数;input param
        :param pstOutParam:结构体输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateFaceRecognitionDB(lLoginID, byref(pstInParam), byref(pstOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ControlDevice(cls, lLoginID: int, type: CtrlType, param: c_void_p = None, waittime: int = 1000) -> int:
        """
        设备控制(param内存由用户申请释放，大小参照type类型对应的结构体); Device control,user malloc param's memory,please refer to the corresponding structure of type
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param type: 控制类型,参考CtrlType；control type, refer to CtrlType in SDK.Enum.py
        :param param:控制类型对应的信息指针地址; pointer to control param
        :param waittime:等待时间; wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        type = c_int(type)
        result = cls.sdk.CLIENT_ControlDevice(lLoginID, type, byref(param), waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ControlDeviceEx(cls, lLoginID: int, type: CtrlType, inParam: c_void_p = None, outParam: c_void_p = None, waittime: int = 1000) -> int:
        """
        设备控制扩展接口(inParam outParam内存由用户申请释放，大小参照type类型对应的结构体); Device control,user malloc param's memory,please refer to the corresponding structure of type
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param type: 控制类型,参考CtrlType；control type, refer to CtrlType in SDK.Enum.py
        :param inParam:控制类型对应的信息指针地址; pointer to control param
        :param outParam:控制结果出参; control return
        :param waittime:等待时间; wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        type = c_int(type)
        result = cls.sdk.CLIENT_ControlDeviceEx(lLoginID, type, byref(inParam), byref(outParam), waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetNewDevConfig(cls, lLoginID: c_int, szCommand: c_char_p, nChannelID: c_int, szOutBuffer: c_char_p, dwOutBufferSize: C_DWORD, error: c_int, waittime: c_int, pReserved: c_void_p = None):
        """
         查询配置信息; Search configuration information
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param szCommand: 类型,参考SDK_Enum.py的CFG_CMD_TYPE；Command,refer to CFG_CMD_TYPE in SDK_Enum.py
        :param nChannelID:通道号;Channel ID
        :param szOutBuffer:数据缓冲区;Out buffer
        :param dwOutBufferSize: 数据大小;Out buffer size
        :param error:错误码;Error code
        :param waittime:等待时间；Wait time
        :param pReserved:保留字段;Reserved
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        szCommand = c_char_p(szCommand.encode())
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        data_buffer = pointer(szOutBuffer)
        pReserved = c_void_p(pReserved)
        error = c_int(0)
        result = cls.sdk.CLIENT_GetNewDevConfig(lLoginID, szCommand, nChannelID, data_buffer, dwOutBufferSize, byref(error), waittime, pReserved)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ParseData(cls, szCommand: c_char_p, szInBuffer: c_char_p, lpOutBuffer: C_LLONG, dwOutBufferSize: C_DWORD, pReserved: c_void_p = None):
        """
         解析查询到的配置信息; Analyze searched config info
        :param szCommand: 类型,参考SDK_Enum.py的CFG_CMD_TYPE；Command,refer to CFG_CMD_TYPE in SDK_Enum.py
        :param szInBuffer:数据缓冲区;data buffer
        :param lpOutBuffer: 结构体输出参数；output param
        :param dwOutBufferSize: 结构体输出参数大小；output param size
        :param pReserved:保留字段;Reserved
        :return:1:成功,0:失败;1:success,0:failed
        """
        szCommand = c_char_p(szCommand.encode())
        szInBuffer = pointer(szInBuffer)
        lpOutBuffer = byref(lpOutBuffer)
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        pReserved = c_void_p(pReserved)
        result = cls.config_sdk.CLIENT_ParseData(szCommand, szInBuffer,lpOutBuffer, dwOutBufferSize, pReserved)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PacketData(cls, szCommand: c_char_p, lpInBuffer: C_LLONG, dwInBufferSize: C_DWORD, szOutBuffer: c_char_p, dwOutBufferSize: C_DWORD):
        """
        组成要设置的配置信息; Constitute the configuration information to be set.
       :param szCommand: 类型,参考SDK_Enum.py的CFG_CMD_TYPE；Command,refer to CFG_CMD_TYPE in SDK_Enum.py
       :param lpInBuffer: 结构体输入参数；input param
       :param dwInBufferSize: 结构体输入参数大小；input param size
       :param szOutBuffer:输出数据缓冲区; out buffer
       :param szOutBuffer:输出数据缓冲区数据大小; out buffer size
       :return:1:成功,0:失败;1:success,0:failed
        """
        szCommand = c_char_p(szCommand.encode())
        lpInBuffer = byref(lpInBuffer)
        dwInBufferSize = C_DWORD(dwInBufferSize)
        szOutBuffer = pointer(szOutBuffer)
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        result = cls.config_sdk.CLIENT_PacketData(szCommand, lpInBuffer, dwInBufferSize, szOutBuffer, dwOutBufferSize)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetNewDevConfig(cls, lLoginID: C_LLONG, szCommand: c_char_p, nChannelID: c_int, szInBuffer: c_char_p, dwInBufferSize: C_DWORD, error: c_int, restart: c_int, waittime: c_int):
        """
        设置配置信息;Set configuration information
       :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
       :param szCommand: 类型,参考SDK_Enum.py的CFG_CMD_TYPE；Command,refer to CFG_CMD_TYPE in SDK_Enum.py
       :param nChannelID:通道号;Channel ID
       :param szInBuffer:输入数据缓冲区;In buffer
       :param dwInBufferSize:输入数据大小;In buffer size
       :param error:错误码;Error code
       :param restart:配置设置后是否需要重启设备,1表示需要重启,0表示不需要重启;reboot device after set config,1 is reboot,0 is not reboot
       :param waittime:等待时间；Wait time
       :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        szCommand = c_char_p(szCommand.encode())
        szInBuffer = pointer(szInBuffer)
        dwInBufferSize = C_DWORD(dwInBufferSize)
        error = c_int(0)
        restart = c_int(restart)
        result = cls.sdk.CLIENT_SetNewDevConfig(lLoginID, szCommand, nChannelID, szInBuffer, dwInBufferSize, byref(error), byref(restart), waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetConfig(cls, lLoginID: C_LLONG, emCfgOpType: c_int, nChannelID: c_int, szOutBuffer: c_void_p, dwOutBufferSize: C_DWORD, waittime: c_int, reserve: c_void_p = None):
        """
        获取配置信息;configuration interface, Get configuration information
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param emCfgOpType:配置类型,参考SDK_Enum.py的NET_EM_CFG_OPERATE_TYPE;Config type,refer to NET_EM_CFG_OPERATE_TYPE in SDK_Enum.py
        :param nChannelID:通道号;Channel ID
        :param szOutBuffer:结构体输出参数;Output param
        :param dwOutBufferSize:结构体输出参数大小;Output param size
        :param waittime:等待时间；wait time
        :param reserve:保留字段;Reserved
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        if reserve != None:
            reserve = c_void_p(reserve)
            result = cls.sdk.CLIENT_GetConfig(lLoginID, emCfgOpType, nChannelID, byref(szOutBuffer), dwOutBufferSize, waittime, byref(reserve))
            if not result:
                print(cls.GetLastErrorMessage())
            return result
        else:
            result = cls.sdk.CLIENT_GetConfig(lLoginID, emCfgOpType, nChannelID, byref(szOutBuffer), dwOutBufferSize,
                                              waittime)
            if not result:
                print(cls.GetLastErrorMessage())
            return result

    @classmethod
    def SetConfig(cls, lLoginID: C_LLONG, emCfgOpType: c_int, nChannelID: c_int, szInBuffer: c_void_p, dwInBufferSize: C_DWORD, waittime: c_int, restart: c_int, reserve: c_void_p = None):
        """
        设置配置信息; configuration interface, Set configuration information
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param emCfgOpType:配置类型,参考SDK_Enum.py的NET_EM_CFG_OPERATE_TYPE;Config type,refer to NET_EM_CFG_OPERATE_TYPE in SDK_Enum.py
        :param nChannelID:通道号;Channel ID
        :param szInBuffer:结构体输入参数;Input param
        :param dwInBufferSize:结构体输入参数大小;Input param size
        :param waittime:等待时间；wait time
        :param restart:配置设置后是否需要重启设备,1表示需要重启,0表示不需要重启;reboot device after set config,1 is reboot,0 is not reboot
        :param reserve:保留字段;Reserved
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        dwInBufferSize = C_DWORD(dwInBufferSize)
        restart = c_int(restart)
        if reserve != None:
            reserve = c_void_p(None)
            result = cls.sdk.CLIENT_SetConfig(lLoginID, emCfgOpType, nChannelID, byref(szInBuffer), dwInBufferSize,
                                              waittime, byref(restart), byref(reserve))
            if not result:
                print(cls.GetLastErrorMessage())
            return result
        else:
            result = cls.sdk.CLIENT_SetConfig(lLoginID, emCfgOpType, nChannelID, byref(szInBuffer), dwInBufferSize,
                                              waittime, byref(restart))
            if not result:
                print(cls.GetLastErrorMessage())
            return result

    @classmethod
    def QuerySystemStatus(cls, lLoginID: C_LLONG, pstuStatus: SDK_SYSTEM_STATUS, nWaitTime: c_int):
        """
        查询系统状态(pstuStatus内存由用户申请释放);  Search system status,user malloc and free pstuStatus's memory
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstuStatus:系统状态缓存；status info buffer
        :param waittime:等待时间；wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        pstuStatus = pointer(pstuStatus)
        result = cls.sdk.CLIENT_QuerySystemStatus(lLoginID, pstuStatus, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryDevState(cls, lLoginID: C_LLONG, nType: c_int, pBuf: c_char_p, nBufLen: c_int, pRetLen: c_int, waittime: c_int):
        """
        查询设备状态(pBuf内存由用户申请释放, 根据nType类型确定相应结构体，至少需要申请结构体大小的内存);  Search device status,user malloc pBuf memory,please refer to query device type to ensure structure,then apply to the memory size of structure
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param nType:对应类型是SDK_Enum.py内的EM_QUERY_DEV_STATE_TYPE;corresponding to EM_QUERY_DEV_STATE_TYPE in SDK_Enum.py
        :param pBuf:设备状态缓存;Device status buffer
        :param nBufLen:设备状态缓存大小;Device status buffer length
        :param pRetLen:返回的设备状态大小;Return device status buffer length
        :param waittime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        pBuf = pointer(pBuf)
        pRetLen = c_int(pRetLen)
        result = cls.sdk.CLIENT_QueryDevState(lLoginID, nType, pBuf, nBufLen, byref(pRetLen), waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FocusControl(cls, lLoginID: C_LLONG, nChannelID: c_int, dwFocusCommand: C_DWORD, nFocus: c_double, nZoom: c_double, reserved: c_void_p, waittime: c_int):
        """
        镜头聚焦控制,dwFocusCommand = 0为聚焦调节,dwFocusCommand = 1为连续聚焦调节,dwFocusCommand = 2为自动聚焦调节,调节焦点至最佳位置。nFocus和nZoom无效; control focus, dwFocusCommand = 0 focus adjucy, dwFocusCommand = 1continuous focus adjustment, dwFocusCommand = 2 auto adjust ,adjust to the best position,nFocus and nZoominvalid
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param nChannelID: 通道号; Channel ID
        :param dwFocusCommand: 聚焦命令,当该值为0时表示聚集调节;当该值为1时表示连续聚焦调节;当该值为2时表示自动聚焦调节，nFocus和nZoom无效; Focus command,When the value is 0, it means focus adjustment; when the value is 1, it means continuous focus adjustment; when the value is 2, it means auto focus adjustment, nFocus and nZoom are invalid
        :param nFocus: 变焦电机的步进相对位置,范围0~1，-1表示重置; The relative stepping position of the focus motor, the range is 0~1, -1 means reset
        :param nZoom:变倍电机的步进相对位置,范围0~1，-1表示重置; The step relative position of the zoom motor, the range is 0~1, -1 means reset
        :param reserved:保留参数;Reserved
        :param waittime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        dwFocusCommand = C_DWORD(dwFocusCommand)
        nFocus = c_double(nFocus)
        nZoom = c_double(nZoom)
        reserved = c_void_p(None)
        result = cls.sdk.CLIENT_FocusControl(lLoginID, nChannelID, dwFocusCommand, nFocus, nZoom, reserved, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PTZControlEx2(cls, lLoginID: int, nChannelID: int, dwPTZCommand: SDK_PTZ_ControlType, lParam1: int, lParam2: int, lParam3: int, dwStop: bool, param4: c_void_p = None) -> int:
        """
        私有云台控制扩展接口,支持三维快速定位,鱼眼,param4由用户申请释放内存，内存大小参照DH_EXTPTZ_ControlType对应的结构体; private PTZ control expansion port , support 3D quick positioning, Fish eye ,user malloc param4's memory,please refer to corresponding structure of DH_EXTPTZ_ControlType
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param nChannelID: 通道号; channel id
        :param dwPTZCommand: PTZ 控制命令; control commands
        :param param1: 控制命令的参数1; Parameter1,details refer to EM_EXTPTZ_ControlType
        :param param2: 控制命令的参数2; Parameter2,details refer to EM_EXTPTZ_ControlType
        :param param3: 控制命令的参数3; Parameter3,details refer to EM_EXTPTZ_ControlType
        :param dwStop: 是否停止; stop or not, effective to PTZ eight-directions operation and lens operation. During other operation, this parameter should fill in false
        :param param4: 控制命令的参数4; support PTZ control extensive command
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        nChannelID = c_int(nChannelID)
        dwPTZCommand = C_DWORD(dwPTZCommand)
        lParam1 = c_long(lParam1)
        lParam2 = c_long(lParam2)
        lParam3 = c_long(lParam3)
        if dwStop:
            dwStop = C_BOOL(1)
        else:
            dwStop = C_BOOL(0)
        result = cls.sdk.CLIENT_DHPTZControlEx2(lLoginID, nChannelID, dwPTZCommand, lParam1, lParam2, lParam3, dwStop, param4)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDistanceRes(cls, lLoginID: int, pInParam: c_void_p, pOutParam: c_void_p, nWaitTime: int = 5000) -> int:
        """
        获取画面中心位置目标的距离; Obtaining the Distance of the Target in the Central Position of the Picture
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam:结构体输入参数,对应结构体 NET_IN_GET_DISTANCE_RES;input param, refer to NET_IN_GET_DISTANCE_RES;
        :param pOutParam:结构体输出参数,对应结构体 NET_OUT_GET_DISTANCE_RES;output param, refer to  NET_OUT_GET_DISTANCE_RES
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetDistanceRes(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryNewSystemInfoEx(cls, lLoginID: c_int, szCommand: CFG_CAP_CMD_TYPE, nChannelID: c_int, szOutBuffer: c_char_p, dwOutBufferSize: C_DWORD, error: c_int, pExtendInfo: c_void_p = None, waittime: c_int = 1000):
        """
         新系统能力查询接口扩展，查询系统能力信息，入参新增扩展数据(以Json格式，具体见配置SDK)(szOutBuffer内存由用户申请释放); New Search system capacity information extend interface(by Json)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param szCommand: 类型,参考SDK_Enum.py的CFG_CAP_CMD_TYPE；Command,refer to CFG_CAP_CMD_TYPE in SDK_Enum.py
        :param nChannelID:通道号;Channel ID
        :param szOutBuffer:数据缓冲区;Out buffer
        :param dwOutBufferSize: 数据大小;Out buffer size
        :param error:错误码;Error code
        :param pExtendInfo:扩展信息; extend info
        :param waittime:等待时间；Wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        szCommand = c_char_p(szCommand.encode())
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        data_buffer = pointer(szOutBuffer)
        error = c_int(0)
        pExtendInfo = c_void_p(pExtendInfo)
        result = cls.sdk.CLIENT_QueryNewSystemInfoEx(lLoginID, szCommand, nChannelID, data_buffer, dwOutBufferSize, byref(error), pExtendInfo, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachPTZStatusProc(cls, lLoginID: int, pstuInPtzStatusProc: NET_IN_PTZ_STATUS_PROC, pstuOutPtzStatusProc: NET_OUT_PTZ_STATUS_PROC, nWaitTime: int = 5000) -> int:
        """
        订阅云台元数据接口,pstuInPtzStatusProc与pstuOutPtzStatusProc内存由用户申请释放; subscribe PTZ metadata port,user malloc memory of pstuInPtzStatusProc and pstuOutPtzStatusProc
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstuInPtzStatusProc:结构体输入参数,对应结构体 NET_IN_PTZ_STATUS_PROC;input param, refer to NET_IN_PTZ_STATUS_PROC;
        :param pstuOutPtzStatusProc:结构体输出参数,对应结构体 NET_OUT_PTZ_STATUS_PROC;output param, refer to  NET_OUT_PTZ_STATUS_PROC
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_AttachPTZStatusProc.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachPTZStatusProc(lLoginID, byref(pstuInPtzStatusProc), byref(pstuOutPtzStatusProc), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachPTZStatusProc(cls, lAttachHandle: int) -> int:
        """
        停止订阅云台元数据接口; stop subscribe PTZ metadata port
        :param lAttachHandle: AttachPTZStatusProc返回值; AttachPTZStatusProc return value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachPTZStatusProc(lAttachHandle)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceBoard_GetTemperatureEx(cls, lLoginID: int, pInParam: NET_IN_GET_TEMPERATUREEX, pOutParam: NET_OUT_GET_TEMPERATUREEX, nWaitTime: int = 5000) -> int:
        """
        获取温度值; Get Face Board Temperature
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam:结构体输入参数,对应结构体 NET_IN_GET_TEMPERATUREEX;input param, refer to NET_IN_GET_TEMPERATUREEX;
        :param pOutParam:结构体输出参数,对应结构体 NET_OUT_GET_TEMPERATUREEX;output param, refer to  NET_OUT_GET_TEMPERATUREEX
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_FaceBoard_GetTemperatureEx(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RadiometryAttach(cls, lLoginID: int, pInParam: NET_IN_RADIOMETRY_ATTACH, pOutParam: NET_OUT_RADIOMETRY_ATTACH, nWaitTime: int) -> int:
        """
        订阅温度分布数据（热图）,pInParam与pOutParam内存由用户申请释放
        Subscribe to temperature distribution data (heat map), pInParam and pOutParam memory will be released by the user's application
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 结构体输入参数 NET_IN_RADIOMETRY_ATTACH; input param NET_IN_RADIOMETRY_ATTACH
        :param pOutParam: 结构体输出参数 NET_OUT_RADIOMETRY_ATTACH; output param NET_OUT_RADIOMETRY_ATTACH
        :param nWaitTime: 等待时间; wait time
        :return 订阅句柄; Subscription handle
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        cls.sdk.CLIENT_RadiometryAttach.restype = C_LLONG
        result = cls.sdk.CLIENT_RadiometryAttach(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RadiometryDetach(cls, lAttachHandle: int) -> int:
        """
        取消订阅温度分布数据,lAttachHandle是 CLIENT_RadiometryAttach 的返回值
        Unsubscribe the temperature distribution data, lAttachHandle is the return value of CLIENT_RadiometryAttach
        :param lAttachHandle: 订阅句柄, CLIENT_RadiometryAttach 的返回值; Subscription handle, The return value of CLIENT_RadiometryAttach
        :return 1:成功,0:失败; 1:success,0:failed
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_RadiometryDetach(lAttachHandle)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RadiometryFetch(cls, lLoginID: int, pInParam: NET_IN_RADIOMETRY_FETCH, pOutParam: NET_OUT_RADIOMETRY_FETCH, nWaitTime: int) -> int:
        """
        通知开始获取热图数据,pInParam与pOutParam内存由用户申请释放
        Notify the start of obtaining heat map data, and the memory of pInParam and pOutParam will be released by the user upon request
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 结构体输入参数 NET_IN_RADIOMETRY_FETCH ; input param NET_IN_RADIOMETRY_FETCH
        :param pOutParam: 结构体输出参数 NET_OUT_RADIOMETRY_FETCH ; output param NET_OUT_RADIOMETRY_FETCH
        :param nWaitTime: 等待时间; wait time
        :return 1:成功,0:失败; 1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        result = cls.sdk.CLIENT_RadiometryFetch(lLoginID, pInParam, pOutParam, nWaitTime)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RadiometryDataParse(cls, pRadiometryData: NET_RADIOMETRY_DATA, pGrayImg: c_short, pTempForPixels: c_float) -> int:
        """
        热图数据解压与转换接口; Heat map data decompression and conversion interface
        :param pRadiometryData: 热图数据,由 fRadiometryAttachCB 获得; Heat map data, obtained by fRadiometryAttachCB
        :param pGrayImg: 解压后的数据，是一张灰度图; The decompressed data is a grayscale image
                        传空指针表示不需要此数据; Passing a null pointer means that this data is not needed
                        用户需保证传入的缓冲区足够大（不小于 图像像素数*sizeof(unsigned short)）; The user needs to ensure that the incoming buffer is large enough (not less than the number of image pixels *sizeof(unsigned short))
                        每个像素对应一个 unsigned short 型数据，表示图像某个像素的热成像灰度（范围 0 ~ 16383）; Each pixel corresponds to an unsigned short data, which represents the thermal imaging grayscale of a certain pixel of the image (range 0 ~ 16383)
                        低地址对应画面左上角，高地址对应画面右下角; The low address corresponds to the upper left corner of the screen, and the high address corresponds to the lower right corner of the screen
        :param pTempForPixels: 每个像素的温度数据; Temperature data for each pixel
                        不能传空指针,否则返回失败; Cannot pass a null pointer, otherwise it will return a failure
                        用户需保证传入的缓冲区足够大（不小于 图像像素数*sizeof(float)）; The user needs to ensure that the incoming buffer is large enough (not less than the number of image pixels *sizeof(float))
                        每个像素对应一个 float 型数据，表示该像素位置的摄氏温度; Each pixel corresponds to a float data, which represents the temperature in degrees Celsius of the pixel location
                        低地址对应画面左上角，高地址对应画面右下角; The low address corresponds to the upper left corner of the screen, and the high address corresponds to the lower right corner of the screen
        :return TRUE 成功; FALSE 失败
        """
        result = cls.sdk.CLIENT_RadiometryDataParse(byref(pRadiometryData), pointer(pGrayImg), pointer(pTempForPixels))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetSoftwareVersion(cls, lLoginID: int, pInParam: NET_IN_GET_SOFTWAREVERSION_INFO, pOutParam: NET_OUT_GET_SOFTWAREVERSION_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取软件版本; get software version
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 结构体输入参数 NET_IN_GET_SOFTWAREVERSION_INFO ; input param NET_IN_GET_SOFTWAREVERSION_INFO
        :param pOutParam: 结构体输出参数 NET_OUT_GET_SOFTWAREVERSION_INFO ; output param NET_OUT_GET_SOFTWAREVERSION_INFO
        :param nWaitTime: 等待时间; wait time
        :return 1:成功,0:失败; 1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetSoftwareVersion(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if result != 1:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindFileEx(cls, lLoginID: int, emType: int, pQueryCondition: c_void_p, reserved: c_char, nWaitTime: int) -> C_LLONG:
        """
        按查询条件查询文件,pQueryCondition由用户申请释放内存，大小参照emType对应的结构体; Query files according to query conditions, pQueryCondition is requested by the user to release memory, and the size refers to the structure corresponding to emType
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emType: 查询类型 参考 EM_FILE_QUERY_TYPE ; Query type Refer to EM_FILE_QUERY_TYPE
        :param pQueryCondition: 查询条件,内容参考emType对应的结构体; Query conditions, content refer to the structure corresponding to emType
        :param reserved: 保留参数 ; reserved
        :param nWaitTime: 等待时间; wait time
        :return 查询句柄; query handle
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_FindFileEx.restype = C_LLONG
        result = cls.sdk.CLIENT_FindFileEx(lLoginID, emType, byref(pQueryCondition), byref(reserved), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindNextFileEx(cls, lFindHandle: int, nFilecount: int, pMediaFileInfo: c_void_p, maxlen: int, reserved: c_void_p, nWaitTime: int) -> int:
        """
        查找文件:nFilecount:需要查询的条数, 返回值为媒体文件条数 返回值<nFilecount则相应时间段内的文件查询完毕
        Find files: nFilecount: the number of files to be queried, the return value is the number of media files If the return value is <nFilecount, the file query in the corresponding time period is completed
        :param lFindHandle: 查询句柄 FindFileEx返回值; query handle, FindFileEx's returns value
        :param nFilecount: 需要查询的条数 ; the number of files to be queried
        :param pMediaFileInfo: 查询信息 参考 MEDIAFILE_TRAFFICCAR_INFO_EX; Query message, refer to MEDIAFILE_TRAFFICCAR_INFO_EX
        :param maxlen: 最大长度 nFilecount * sizeof(MEDIAFILE_TRAFFICCAR_INFO_EX); max length, nFilecount * sizeof(MEDIAFILE_TRAFFICCAR_INFO_EX)
        :param reserved: 保留参数 ; reserved
        :param nWaitTime: 等待时间; wait time
        :return 媒体文件条数; number of media files
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_FindNextFileEx(lFindHandle, nFilecount, byref(pMediaFileInfo), maxlen, byref(reserved), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindCloseEx(cls, lFindHandle: int) -> C_BOOL:
        """
        结束录像文件查找
        End video file search
        :param lFindHandle: 查询句柄 FindFileEx返回值; query handle, FindFileEx's returns value
        :return 返回结果; return results
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_FindCloseEx(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DownloadMediaFile(cls, lLoginID: int, emType: int, lpMediaFileInfo: c_void_p, sSavedFileName: c_char_p, cbDownLoadPos: fDownLoadPosCallBack, dwUserData: C_LDWORD, reserved: c_void_p) -> C_LLONG:
        """
        下载指定的智能分析数据 - 图片,lpMediaFileInfo由用户申请释放内存，内存大小参照emType确定对应的结构体
        Download the specified intelligent analysis data - picture, lpMediaFileInfo is requested by the user to release the memory, and the memory size refers to emType to determine the corresponding structure
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emType: 查询类型 参考 EM_FILE_QUERY_TYPE ; Query type Refer to EM_FILE_QUERY_TYPE
        :param lpMediaFileInfo: 查询信息 参考 MEDIAFILE_TRAFFICCAR_INFO_EX; Query message, refer to MEDIAFILE_TRAFFICCAR_INFO_EX
        :param sSavedFileName: 保存文件名称; save file name
        :param cbDownLoadPos: 回调函数; callback
        :param dwUserData: 用户数据; user data
        :param reserved: 保留参数 ; reserved
        :return 下载句柄; download handle
        """
        lLoginID = C_LLONG(lLoginID)
        dwUserData = C_LDWORD(dwUserData)
        cls.sdk.CLIENT_DownloadMediaFile.restype = C_LLONG
        result = cls.sdk.CLIENT_DownloadMediaFile(lLoginID, emType, byref(lpMediaFileInfo), sSavedFileName, cbDownLoadPos, dwUserData, byref(reserved))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateTrafficList(cls, lLoginID: int, pInParam: NET_IN_OPERATE_TRAFFIC_LIST_RECORD, pOutParam: NET_OUT_OPERATE_TRAFFIC_LIST_RECORD, nWaitTime: int = 3000) -> C_BOOL:
        """
        可用名单操作,pstInParam与pstOutParam内存由用户申请释放; Available list operations, the memory of pstInParam and pstOutParam is released by the user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam:输入参数;input param
        :param pOutParam:输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateTrafficList(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindRecord(cls, lLoginID: int, pInParam: NET_IN_FIND_RECORD_PARAM, pOutParam: NET_OUT_FIND_RECORD_PARAM, nWaitTime: int = 3000) -> C_BOOL:
        """
        按查询条件查询记录,pInParam与pOutParam内存由用户申请释放; by search filter search record,user malloc memory of pInParam and pOutParam
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值;user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam:输入参数;input param
        :param pOutParam:输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_FindRecord(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindNextRecord(cls, pInParam: NET_IN_FIND_NEXT_RECORD_PARAM, pOutParam: NET_OUT_FIND_NEXT_RECORD_PARAM, nWaitTime: int = 3000) -> C_BOOL:
        """
        查找记录:nFilecount:需要查询的条数, 返回值为媒体文件条数 返回值<nFilecount则相应时间段内的文件查询完毕,pInParam与pOutParam内存由用户申请释放;
        search record :nFilecount: need search items,  return value as media file items  return value<nFilecountas corresponding period file search complete,user malloc memory of pInParam and pOutParam
        :param pInParam:输入参数;input param
        :param pOutParam:输出参数;output param
        :param nWaitTime:等待时间;wait time
        :return:1:成功,0:失败;1:success,0:failed
        """
        result = cls.sdk.CLIENT_FindNextRecord(byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindRecordClose(cls, lFindHandle: int) -> C_BOOL:
        """
        结束记录查找; end record search
        :param lFindHandle: 查询句柄，FindRecord返回值;user find ID,FindRecord's returns value
        :return:1:成功,0:失败;1:success,0:failed
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_FindRecordClose(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryDeviceUTC(cls, lLoginID: int, pDeviceTime: NET_UTCTIME, waittime: int) -> C_BOOL:
        """
        查询设备当前UTC时间接口; Query the current UTC time interface of the device
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pDeviceTime: utc时间结构体 对应 NET_UTCTIME ; The UTC time structure corresponds to net_ UTCTIME
        :param waittime: 超时时间; waittime
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_QueryDeviceUTC(lLoginID, byref(pDeviceTime), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DownloadRemoteFile(cls, lLoginID: int, pInParam: NET_IN_DOWNLOAD_REMOTE_FILE, pOutParam: NET_OUT_DOWNLOAD_REMOTE_FILE, waittime: int) -> C_BOOL:
        """
        查询设备当前UTC时间接口; Query the current UTC time interface of the device
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 输入参数 对应 NET_IN_DOWNLOAD_REMOTE_FILE ; The input parameter corresponds to NET_IN_DOWNLOAD_REMOTE_FILE
        :param pOutParam: 输出参数 对应 NET_OUT_DOWNLOAD_REMOTE_FILE; The output parameter corresponds to NET_OUT_DOWNLOAD_REMOTE_FILE
        :param waittime: 超时时间; waittime
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_DownloadRemoteFile(lLoginID, byref(pInParam), byref(pOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryTransComParams(cls, lLoginID: int, TransComType: int, pCommState: NET_A_COMM_STATE, nWaitTime: int) -> C_BOOL:
        """
        查询透明串口状态(pCommState内存由用户申请释放); Query transparent serial port status (pcommstate memory is released by user application)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param TransComType: 高2个字节表示串口序号,低2个字节表示串口类型,目前类型支持0：串口,1:485; The upper 2 bytes of transcomtype represent serial port serial number and the lower 2 bytes represent serial port type
        :param pCommState: 串口状态参数 参考 NET_A_COMM_STATE; Serial port status parameters, reference NET_A_COMM_STATE
        :param nWaitTime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        TransComType = c_int(TransComType)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_QueryTransComParams(lLoginID, TransComType, byref(pCommState), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def CreateTransComChannel(cls, lLoginID: int, TransComType: int, baudrate: int, databits: int, stopbits: int, parity: int, cbTransCom: fTransComCallBack, dwUser: int) -> C_LLONG:
        """
        创建透明串口通道,TransComType高2个字节表示串口序号,低2个字节表示串口类型,目前类型支持0：串口,1:485;
        Create a transparent serial port channel. The upper 2 bytes of transcomtype represent serial port serial number and the lower 2 bytes represent serial port type. At present, the type supports 0: serial port and 1:485
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param TransComType: 串口序号及类型; Serial port serial number and type
        :param baudrate: 波特率; baudrate
        :param databits: 数据位; databits
        :param stopbits: 停止位; stopbits
        :param parity: 奇偶; parity
        :param cbTransCom: 数据回调函数; data callback
        :param dwUser: 用户数据; user data
        :return: 串口通道句柄; Serial port channel handle
        """
        lLoginID = C_LLONG(lLoginID)
        TransComType = c_int(TransComType)
        baudrate = c_uint(baudrate)
        databits = c_uint(databits)
        stopbits = c_uint(stopbits)
        parity = c_uint(parity)
        cls.sdk.CLIENT_CreateTransComChannel.restype = C_LLONG
        result = cls.sdk.CLIENT_CreateTransComChannel(lLoginID, TransComType, baudrate, databits, stopbits, parity, cbTransCom, C_LDWORD(dwUser))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SendTransComData(cls, lTransComChannel: C_LLONG, pBuffer: c_char_p, dwBufSize: int) -> C_BOOL:
        """
        透明串口发送数据(pBuffer内存由用户申请释放); Send data through transparent serial port (Pbuffer memory is released by user application)
        :param lTransComChannel: 串口通道句柄; Serial port channel handle
        :param pBuffer: 待发送数据; data to be sent
        :param dwBufSize: 数据的长度; data size
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lTransComChannel = C_LLONG(lTransComChannel)
        dwBufSize = C_DWORD(dwBufSize)
        result = cls.sdk.CLIENT_SendTransComData(lTransComChannel, pBuffer, dwBufSize)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DestroyTransComChannel(cls, lTransComChannel: C_LLONG) -> C_BOOL:
        """
        释放通明串口通道; Release the open serial port channel
        :param lTransComChannel: 串口通道句柄; Serial port channel handle
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lTransComChannel = C_LLONG(lTransComChannel)
        result = cls.sdk.CLIENT_DestroyTransComChannel(lTransComChannel)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AddAnalyseTask(cls, lLoginID: int, emDataSourceType: EM_DATA_SOURCE_TYPE, pInParam: c_void_p, pOutParam: NET_OUT_ADD_ANALYSE_TASK, nWaitTime: int) -> C_BOOL:
        """
        添加智能分析任务, 输入参数pInParam的结构体类型根据emDataSourceType的值来决定, pInParam 和 pOutParam 资源由用户申请和释放;
        Add an intelligent analysis task. The structure type of the input parameter pinparam is determined according to the value of emdatasourcetype. Pinparam and poutparam resources are applied and released by the user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emDataSourceType: 任务类型,参考 EM_DATA_SOURCE_TYPE ; Task type, refer to EM_DATA_SOURCE_TYPE
        :param pInParam: 根据emDataSourceType的值来决定; Determined by the value of emDataSourceType
        :param pOutParam: 返回参数 参考 NET_OUT_ADD_ANALYSE_TASK; Return parameter reference NET_OUT_ADD_ANALYSE_TASK
        :param nWaitTime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        emDataSourceType = c_int(emDataSourceType)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_AddAnalyseTask(lLoginID, emDataSourceType, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FindAnalyseTask(cls, lLoginID: int, pInParam: NET_IN_FIND_ANALYSE_TASK, pOutParam: NET_OUT_FIND_ANALYSE_TASK, nWaitTime: int) -> C_BOOL:
        """
        查找智能分析任务信息, pInParam 和 pOutParam 资源由用户申请和释放
        Find intelligent analysis task information. Pinparam and poutparam resources are applied and released by users
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 查找条件 参考 NET_IN_FIND_ANALYSE_TASK; Find condition reference NET_IN_FIND_ANALYSE_TASK
        :param pOutParam: 返回参数 参考 NET_OUT_FIND_ANALYSE_TASK; Return parameter reference NET_OUT_FIND_ANALYSE_TASK
        :param nWaitTime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FindAnalyseTask(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RemoveAnalyseTask(cls, lLoginID: int, pInParam: NET_IN_REMOVE_ANALYSE_TASK, pOutParam: NET_OUT_REMOVE_ANALYSE_TASK, nWaitTime: int) -> C_BOOL:
        """
        删除(停止)智能分析任务, pInParam 和 pOutParam 资源由用户申请和释放
        Delete (stop) the intelligent analysis task, and the pinparam and poutparam resources are applied and released by the user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 删除结构 参考 NET_IN_REMOVE_ANALYSE_TASK; delete struct reference NET_IN_REMOVE_ANALYSE_TASK
        :param pOutParam: 返回参数 参考 NET_OUT_REMOVE_ANALYSE_TASK; Return parameter reference NET_OUT_REMOVE_ANALYSE_TASK
        :param nWaitTime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_RemoveAnalyseTask(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def PushAnalysePictureFileByRule(cls, lLoginID: int, pInParam: NET_IN_PUSH_ANALYSE_PICTURE_FILE_BYRULE, pOutParam: NET_OUT_PUSH_ANALYSE_PICTURE_FILE_BYRULE, nWaitTime: int) -> C_BOOL:
        """
        推送智能分析图片文件和规则信息，当CLIENT_AddAnalyseTask的数据源类型emDataSourceType为 EM_DATA_SOURCE_PUSH_PICFILE_BYRULE 时使用
        Push intelligent analysis of picture files and rule information. It is used when the data source type emDataSourceType of CLIENT_AddAnalyseTask is EM_DATA_SOURCE_PUSH_PICFILE_BYRULE
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 入参 参考 NET_IN_PUSH_ANALYSE_PICTURE_FILE_BYRULE; InParam reference NET_IN_PUSH_ANALYSE_PICTURE_FILE_BYRULE
        :param pOutParam: 出参 参考 NET_OUT_PUSH_ANALYSE_PICTURE_FILE_BYRULE; OutParam reference NET_OUT_PUSH_ANALYSE_PICTURE_FILE_BYRULE
        :param nWaitTime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_PushAnalysePictureFileByRule(lLoginID, byref(pInParam), byref(pOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachAnalyseTaskState(cls, lLoginID: int, pInParam: NET_IN_ATTACH_ANALYSE_TASK_STATE, nWaitTime: int) -> C_LLONG:
        """
        订阅智能分析任务状态, pInParam 资源由用户申请和释放; Subscribe to intelligent analysis task status, and pinparam resources are applied and released by users
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 入参 参考 NET_IN_ATTACH_ANALYSE_TASK_STATE; InParam reference NET_IN_ATTACH_ANALYSE_TASK_STATE
        :param nWaitTime: 超时时间; waittime
        :return: 订阅句柄; attach handle
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachAnalyseTaskState.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachAnalyseTaskState(lLoginID, byref(pInParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachAnalyseTaskResult(cls, lLoginID: int, pInParam: NET_IN_ATTACH_ANALYSE_RESULT, nWaitTime: int) -> C_LLONG:
        """
        订阅智能分析结果, pInParam 资源由用户申请和释放; Subscribe to intelligent analysis results, and pinparam resources are applied and released by users
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 入参 参考 NET_IN_ATTACH_ANALYSE_RESULT; InParam reference NET_IN_ATTACH_ANALYSE_RESULT
        :param nWaitTime: 超时时间; waittime
        :return: 订阅句柄; attach handle
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachAnalyseTaskResult.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachAnalyseTaskResult(lLoginID, byref(pInParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachAnalyseTaskResult(cls, lAttachHandle: C_LLONG) -> C_BOOL:
        """
        取消订阅智能分析结果, lAttachHandle 为 CLIENT_AttachAnalyseTaskResult接口的返回值;
        Unsubscribe from intelligent analysis results, and the lAttachHandle is CLIENT_AttachAnalyseTaskResult Return value
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachAnalyseTaskResult(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def MatrixGetCameras(cls, lLoginID: int, pInParam: NET_A_IN_MATRIX_GET_CAMERAS, pOutParam: NET_A_OUT_MATRIX_GET_CAMERAS, waittime: int) -> C_BOOL:
        """
        获取所有有效显示源,pInParam与pOutParam内存由用户申请释放; Obtain all valid display sources,pInParam and pOutParam memory by the user to request release
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 输入参数 对应 NET_A_IN_MATRIX_GET_CAMERAS ; The input parameter corresponds to NET_A_IN_MATRIX_GET_CAMERAS
        :param pOutParam: 输出参数 对应 NET_A_OUT_MATRIX_GET_CAMERAS; The output parameter corresponds to NET_A_OUT_MATRIX_GET_CAMERAS
        :param waittime: 超时时间; waittime
        :return:1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_MatrixGetCameras(lLoginID, byref(pInParam), byref(pOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachStatusRTMPManager(cls, lLoginID: int, pInParam: NET_IN_RTMP_MANAGER_ATTACH_STATUS, pOutParam: NET_OUT_RTMP_MANAGER_ATTACH_STATUS, waittime: int) -> C_LLONG:
        """
        订阅推流状态变化及失败原因; Subscription push flow status changes and failure causes
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 输入参数 对应 NET_IN_RTMP_MANAGER_ATTACH_STATUS ; The input parameter corresponds to NET_IN_RTMP_MANAGER_ATTACH_STATUS
        :param pOutParam: 输出参数 对应 NET_OUT_RTMP_MANAGER_ATTACH_STATUS; The output parameter corresponds to NET_OUT_RTMP_MANAGER_ATTACH_STATUS
        :param waittime: 超时时间; waittime
        :return: 订阅句柄; subscription handle
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_AttachStatusRTMPManager.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachStatusRTMPManager(lLoginID, byref(pInParam), byref(pOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachStatusRTMPManager(cls, lAttachStatusHandle: int, pInParam: NET_IN_RTMP_MANAGER_DETACH_STATUS, pOutParam: NET_OUT_RTMP_MANAGER_DETACH_STATUS) -> C_LLONG:
        """
        取消订阅推流状态变化及失败原因; Unsubscribe push flow status changes and failure causes
        :param lAttachStatusHandle: 订阅句柄，AttachStatusRTMPManager返回值; subscribe handle, AttachStatusRTMPManager's returns value
        :param pInParam: 输入参数 对应 NET_IN_RTMP_MANAGER_DETACH_STATUS ; The input parameter corresponds to NET_IN_RTMP_MANAGER_DETACH_STATUS
        :param pOutParam: 输出参数 对应 NET_OUT_RTMP_MANAGER_DETACH_STATUS; The output parameter corresponds to NET_OUT_RTMP_MANAGER_DETACH_STATUS
        :return: 句柄; handle
        """
        lAttachStatusHandle = C_LLONG(lAttachStatusHandle)
        cls.sdk.CLIENT_DetachStatusRTMPManager.restype = C_LLONG
        result = cls.sdk.CLIENT_DetachStatusRTMPManager(lAttachStatusHandle, byref(pInParam), byref(pOutParam))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateRTMPManager(cls, lLoginID: int, emtype: EM_A_NET_EM_RTMP_MANAGER_OPER_TYPE, pstInParam: c_void_p, pstOutParam: c_void_p, waittime: int) -> C_BOOL:
        """
        RTMP推流操作接口; RTMP push stream operation interface
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: RTMP推流操作类型; RTMP push stream operation type
        :param pstInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateRTMPManager(lLoginID, emtype, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetPushInfosRTMPManager(cls, lLoginID: int, pstuInParam: NET_IN_RTMP_MANAGER_GETPUSHINFOS, pstuOutParam: NET_OUT_RTMP_MANAGER_GETPUSHINFOS, waittime: int) -> C_BOOL:
        """
        获取设备已开启RTMP推流任务的信息; Gets the information that the RTMP stream push task is enabled on the device
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstuInParam: 输入参数 对应 NET_IN_RTMP_MANAGER_GETPUSHINFOS ; The input parameter corresponds to NET_IN_RTMP_MANAGER_GETPUSHINFOS
        :param pstuOutParam: 输出参数 对应 NET_OUT_RTMP_MANAGER_GETPUSHINFOS; The output parameter corresponds to NET_OUT_RTMP_MANAGER_GETPUSHINFOS
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetPushInfosRTMPManager(lLoginID, byref(pstuInParam), byref(pstuOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ManualSnap(cls, lLoginID: int, pInParam: NET_IN_MANUAL_SNAP, pOutParam: NET_OUT_MANUAL_SNAP, waittime: int) -> C_BOOL:
        """
        手动抓图, 支持并发调用; Manual capture, support concurrent invocation
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 输入参数 对应 NET_IN_MANUAL_SNAP ; The input parameter corresponds to NET_IN_MANUAL_SNAP
        :param pOutParam: 输出参数 对应 NET_OUT_MANUAL_SNAP; The output parameter corresponds to NET_OUT_MANUAL_SNAP
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_ManualSnap(lLoginID, byref(pInParam), byref(pOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryUserInfoEx(cls, lLoginID: int, info: NET_A_USER_MANAGE_INFO_EX, waittime: int) -> C_BOOL:
        """
        查询用户信息--扩展(info内存由用户申请释放,大小为sizeof(NET_A_USER_MANAGE_INFO_EX)); Query user information -- expand (info memory is freed by user request, size is sizeof(NET_A_USER_MANAGE_INFO_EX))
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param info: 输入参数 对应 NET_A_USER_MANAGE_INFO_EX ; The input parameter corresponds to NET_A_USER_MANAGE_INFO_EX
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_QueryUserInfoEx(lLoginID, byref(info), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateUserInfoEx(cls, lLoginID: int, nOperateType: EM_OPERATE_USER_TYPE, opParam: c_void_p, subParam: c_void_p, waittime: int) -> C_BOOL:
        """
        操作设备用户--扩展(opParam, subParam内存由用户申请释放,根据nOperateType对应的类型找到相应的结构体，进而确定申请内存大小);
        Operation device user -- expansion (opParam, subParam memory is released by the user, find the corresponding structure according to the type of nOperateType, and then determine the size of the applied memory)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param nOperateType: 操作类型; operation type
        :param opParam: 输入参数 由nOperateType类型决定结构体类型; The input parameter determines the structure type by the nOperateType type
        :param subParam: 输出参数 由nOperateType类型决定结构体类型; The output parameter determines the structure type by the nOperateType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateUserInfoEx(lLoginID, nOperateType, byref(opParam), byref(subParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryUserInfoNew(cls, lLoginID: int, info: NET_A_USER_MANAGE_INFO_NEW, pReserved: c_void_p, waittime: int) -> C_BOOL:
        """
        查询用户信息--最大支持64通道设备(info内存由用户申请释放); Query user information -- support 64 channel devices at most (info memory is released by user application)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param info: 输入参数 对应 NET_A_USER_MANAGE_INFO_NEW ; The input parameter corresponds to NET_A_USER_MANAGE_INFO_NEW
        :param pReserved: 保留字段; reserved
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_QueryUserInfoNew(lLoginID, byref(info), byref(pReserved), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateUserInfoNew(cls, lLoginID: int, nOperateType: EM_OPERATE_USER_TYPE, opParam: c_void_p, subParam: c_void_p, pRetParam: c_void_p, waittime: int) -> C_BOOL:
        """
        操作设备用户--扩展(opParam, subParam内存由用户申请释放,根据nOperateType对应的类型找到相应的结构体，进而确定申请内存大小);
        Operation device user -- expansion (opParam, subParam memory is released by the user, find the corresponding structure according to the type of nOperateType, and then determine the size of the applied memory)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param nOperateType: 操作类型; operation type
        :param opParam: 输入参数 由nOperateType类型决定结构体类型; The input parameter determines the structure type by the nOperateType type
        :param subParam: 输出参数 由nOperateType类型决定结构体类型; The output parameter determines the structure type by the nOperateType type
        :param pRetParam: 用户数据; user data
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateUserInfoNew(lLoginID, nOperateType, byref(opParam), byref(subParam), byref(pRetParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AddOnvifUser(cls, lLoginID: int, pstuInParam: NET_IN_ADD_ONVIF_USER_INFO, pstuOutParam: NET_OUT_ADD_ONVIF_USER_INFO, waittime: int) -> C_BOOL:
        """
        添加Onvif用户 pstuInParam/pstuOutParam内存由用户申请/释放; Add Onvif user pstuInParam/pstuOutParam memory allocated/released by user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstuInParam: 输入参数 对应 NET_IN_ADD_ONVIF_USER_INFO ; The input parameter corresponds to NET_IN_ADD_ONVIF_USER_INFO
        :param pstuOutParam: 输出参数 对应 NET_OUT_ADD_ONVIF_USER_INFO; The output parameter corresponds to NET_OUT_ADD_ONVIF_USER_INFO
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_AddOnvifUser(lLoginID, byref(pstuInParam), byref(pstuOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ModifyOnvifUser(cls, lLoginID: int, pstInParam: NET_IN_MODIFYONVIF_USER_INFO, pstOutParam: NET_OUT_MODIFYONVIF_USER_INFO, waittime: int) -> C_BOOL:
        """
        修改Onvif用户（只能修改非 admin用户）pstInParam/pstOutParam内存由用户申请/释放;Modify the Onvif user (only non-admin users can be modified). PstInParam /pstOutParam The memory is allocated or released by the user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam: 输入参数 对应 NET_IN_MODIFYONVIF_USER_INFO ; The input parameter corresponds to NET_IN_MODIFYONVIF_USER_INFO
        :param pstOutParam: 输出参数 对应 NET_OUT_MODIFYONVIF_USER_INFO; The output parameter corresponds to NET_OUT_MODIFYONVIF_USER_INFO
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_ModifyOnvifUser(lLoginID, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetOnvifUserInfoAll(cls, lLoginID: int, pstInParam: NET_IN_GETONVIF_USERINFO_ALL_INFO, pstOutParam: NET_OUT_GETONVIF_USERINFO_ALL_INFO, waittime: int) -> C_BOOL:
        """
        获取Onvif用户信息, pstuInParam/pstuOutParam内存由用户申请/释放; Get Onvif user message, pstuInParam/pstuOutParam memory allocated/released by user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam: 输入参数 对应 NET_IN_GETONVIF_USERINFO_ALL_INFO ; The input parameter corresponds to NET_IN_GETONVIF_USERINFO_ALL_INFO
        :param pstOutParam: 输出参数 对应 NET_OUT_GETONVIF_USERINFO_ALL_INFO; The output parameter corresponds to NET_OUT_GETONVIF_USERINFO_ALL_INFO
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetOnvifUserInfoAll(lLoginID, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ModifyOnvifUserPassword(cls, lLoginID: int, pstInParam: NET_IN_MODIFYONVIF_PASSWORD_INFO, pstOutParam: NET_OUT_MODIFYONVIF_PASSWORD_INFO, waittime: int) -> C_BOOL:
        """
        修改Onvif用户密码, pstInParam/pstOutParam 内存由用户申请/释放; Change the password of the Onvif user. PstInParam /pstOutParam memory is allocated or released by the user
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam: 输入参数 对应 NET_IN_MODIFYONVIF_PASSWORD_INFO ; The input parameter corresponds to NET_IN_MODIFYONVIF_PASSWORD_INFO
        :param pstOutParam: 输出参数 对应 NET_OUT_MODIFYONVIF_PASSWORD_INFO; The output parameter corresponds to NET_OUT_MODIFYONVIF_PASSWORD_INFO
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_ModifyOnvifUserPassword(lLoginID, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartUpgradeEx2(cls, lLoginID: int, emType: EM_UPGRADE_TYPE, pchFileName: c_char_p, cbUpgrade: fUpgradeCallBackEx, dwUser: int) -> C_LLONG:
        """
        开始升级设备程序--扩展支持G以上文件升级; Start upgrade device program - The extension supports upgrade of files above G
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emType: 操作类型 参考 EM_UPGRADE_TYPE; operation type, corresponds to EM_UPGRADE_TYPE
        :param pchFileName: 升级包本地路径; Local path of the upgrade package
        :param cbUpgrade: 回调函数 进度回调; callback, Progress callback
        :param dwUser: 用户数据; user data
        :return: 升级句柄; upgrade handle
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_StartUpgradeEx2.restype = C_LLONG
        result = cls.sdk.CLIENT_StartUpgradeEx2(lLoginID, emType, pchFileName, cbUpgrade, C_LDWORD(dwUser))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SendUpgrade(cls, lUpgradeID: int) -> C_BOOL:
        """
        发送数据; send data
        :param lUpgradeID: 升级句柄, StartUpgradeEx2返回值; upgrade handle,StartUpgradeEx2 returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        lUpgradeID = C_LLONG(lUpgradeID)
        result = cls.sdk.CLIENT_SendUpgrade(lUpgradeID)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopUpgrade(cls, lUpgradeID: int) -> C_BOOL:
        """
        结束升级设备程序; The upgrade procedure is complete
        :param lUpgradeID: 升级句柄, StartUpgradeEx2返回值; upgrade handle,StartUpgradeEx2 returns value
        :return:result:成功：1，失败：0；succeed：1，failed：0
        """
        lUpgradeID = C_LLONG(lUpgradeID)
        result = cls.sdk.CLIENT_StopUpgrade(lUpgradeID)
        if result == 0:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateAccessUserService(cls, lLoginID: int, emtype: EM_A_NET_EM_ACCESS_CTL_USER_SERVICE, pstInParam, pstOutParam, waittime: int) -> C_BOOL:
        """
        门禁人员信息管理接口; Access control personnel information management interface
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: 人员信息操作类型; Personnel information operation type
        :param pstInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateAccessUserService(lLoginID, emtype, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateAccessFaceService(cls, lLoginID: int, emtype: EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE, pstInParam, pstOutParam, waittime: int) -> C_BOOL:
        """
        门禁人脸信息管理接口; Access control face information management interface
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: 人脸信息操作类型; Face information operation type
        :param pstInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateAccessFaceService(lLoginID, emtype, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateAccessCardService(cls, lLoginID: int, emtype: EM_A_NET_EM_ACCESS_CTL_CARD_SERVICE, pstInParam, pstOutParam, waittime: int) -> C_BOOL:
        """
        门禁卡片信息管理接口; Access control card information management interface
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: 卡片信息操作类型; Card information operation type
        :param pstInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_OperateAccessCardService(lLoginID, emtype, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryFurthestRecordTime(cls, lLoginID: int, nRecordFileType: int, pchCardid: c_char_p, pFurthrestTime: NET_FURTHEST_RECORD_TIME, waittime: int) -> C_BOOL:
        """
        查询最早录像时间(pFurthrestTime内存由用户申请释放); Query the earliest recording time (pfurthresttime memory is released by the user's request)
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param nRecordFileType: 录像文件类型, 参考 EM_VIDEO_FILE_TYPE; Video file type, reference resources EM_VIDEO_FILE_TYPE
        :param pchCardid: 输入参数 由nRecordFileType类型决定类型; The input parameter determines the type by the nRecordFileType type
        :param pFurthrestTime: 输入参数 参考 NET_FURTHEST_RECORD_TIME; Input parameter reference NET_FURTHEST_RECORD_TIME
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_QueryFurthestRecordTime(lLoginID, nRecordFileType, pchCardid, byref(pFurthrestTime), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetStorageBoundTimeEx(cls, lLoginID: int, pInParam: NET_IN_GET_BOUND_TIMEEX, pOutParam: NET_OUT_GET_BOUND_TIMEEX, waittime: int) -> C_BOOL:
        """
        获取录像时间范围; Obtain the recording time range
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pInParam: 输入参数 对应 NET_IN_GET_BOUND_TIMEEX ; The input parameter corresponds to NET_IN_GET_BOUND_TIMEEX
        :param pOutParam: 输出参数 对应 NET_OUT_GET_BOUND_TIMEEX; The output parameter corresponds to NET_OUT_GET_BOUND_TIMEEX
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetStorageBoundTimeEx(lLoginID, byref(pInParam), byref(pOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ModifyDeviceEx(cls, pInBuf: NET_IN_MODIFY_IP, pOutBuf: NET_OUT_MODIFY_IP, waittime: int) -> C_BOOL:
        """
        修改设备IP (pDevNetInfo内存由用户申请释放); Modify the device IP (pDevNetInfo memory is released by the user's request)
        :param pInBuf: 输入参数 对应 NET_IN_MODIFY_IP ; The input parameter corresponds to NET_IN_MODIFY_IP
        :param pOutBuf: 输出参数 对应 NET_OUT_MODIFY_IP; The output parameter corresponds to NET_OUT_MODIFY_IP
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        result = cls.sdk.CLIENT_ModifyDeviceEx(byref(pInBuf), byref(pOutBuf), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetAlarmRegionInfo(cls, lLoginID: int, emtype: EM_A_NET_EM_SET_ALARMREGION_INFO, pstuInParam, pstuOutParam, waittime: int) -> C_BOOL:
        """
        报警主机设置操作; alarm host setting operation
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: 操作类型; operation type
        :param pstuInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pstuOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_SetAlarmRegionInfo(lLoginID, emtype, byref(pstuInParam), byref(pstuOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetAlarmRegionInfo(cls, lLoginID: int, emtype: EM_A_NET_EM_GET_ALARMREGION_INFO, pstuInParam, pstuOutParam, waittime: int) -> C_BOOL:
        """
        报警主机获取操作; alarm host acquisition operation
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param emtype: 操作类型; operation type
        :param pstuInParam: 输入参数 由emtype类型决定结构体类型; The input parameter determines the structure type by the emType type
        :param pstuOutParam: 输出参数 由emtype类型决定结构体类型; The output parameter determines the structure type by the emType type
        :param waittime: 超时时间; waittime
        :return: 1:成功,0:失败;1:success,0:failed
        """
        lLoginID = C_LLONG(lLoginID)
        result = cls.sdk.CLIENT_GetAlarmRegionInfo(lLoginID, emtype, byref(pstuInParam), byref(pstuOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachRadarAlarmPointInfo(cls, lLoginID: int, pstInParam: NET_IN_RADAR_ALARMPOINTINFO, pstOutParam: NET_OUT_RADAR_ALARMPOINTINFO, waittime: int) -> C_LLONG:
        """
        订阅雷达的报警点信息; Subscribe to radar alarm point information
        :param lLoginID: 登录句柄，LoginWithHighLevelSecurity返回值; user LoginID,LoginWithHighLevelSecurity's returns value
        :param pstInParam: 输入参数 参考结构体 NET_IN_RADAR_ALARMPOINTINFO; Input parameter reference structure NET_IN_RADAR_ALARMPOINTINFO
        :param pstOutParam: 输出参数 参考结构体 NET_OUT_RADAR_ALARMPOINTINFO; Output parameter reference structure NET_OUT_RADAR_ALARMPOINTINFO
        :param waittime: 超时时间; waittime
        :return: 订阅句柄; attach handle
        """
        lLoginID = C_LLONG(lLoginID)
        cls.sdk.CLIENT_AttachRadarAlarmPointInfo.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachRadarAlarmPointInfo(lLoginID, byref(pstInParam), byref(pstOutParam), c_int(waittime))
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachRadarAlarmPointInfo(cls, lAttachHandle: int) -> C_BOOL:
        """
        取消订阅雷达的报警点信息; Unsubscribe radar alarm point information
        :param lAttachHandle:订阅句柄，AttachRadarAlarmPointInfo接口返回值；Attach handle,return value of AttachRadarAlarmPointInfo
        :return:1:成功,0:失败;1:success,0:failed
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachRadarAlarmPointInfo(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def MatchTwoFaceImage(cls, lLoginID: int, pstInParam: NET_MATCH_TWO_FACE_IN, pstOutParam: NET_MATCH_TWO_FACE_OUT, nWaitTime: int) -> C_BOOL:
        """
        计算两张人脸图片的相似度faceRecognitionServer.matchTwoFace,pstInParam与pstOutParam内存由用户申请释放
        calculate the similarity of two face images,user malloc and free memory of pstInParam and pstOutParam
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_MatchTwoFaceImage(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartMultiFindFaceRecognition(cls, lLoginID: int, pstInParam: NET_IN_STARTMULTIFIND_FACERECONGNITION, pstOutParam: NET_OUT_STARTMULTIFIND_FACERECONGNITION, nWaitTime: int) -> C_BOOL:
        """
        开始人脸检测/注册库的多通道查询
        start face detection / registry multi channel query
        """
        lLoginID = C_LLONG(lLoginID)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_StartMultiFindFaceRecognition(lLoginID, byref(pstInParam), byref(pstOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachFaceFindState(cls, lLoginID: int, pstInParam: NET_IN_FACE_FIND_STATE, pstOutParam: NET_OUT_FACE_FIND_STATE, nWaitTime: int) -> C_LLONG:
        """
        订阅人脸查询状态,pstInParam与pstOutParam内存由用户申请释放
        attach face find state,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachFaceFindState.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachFaceFindState(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindFaceRecognition(cls, pstInParam: NET_IN_DOFIND_FACERECONGNITION, pstOutParam: NET_OUT_DOFIND_FACERECONGNITION, nWaitTime: int) -> C_BOOL:
        """
        查找目标识别结果:nFilecount:需要查询的条数, 返回值为媒体文件条数 返回值<nFilecount则相应时间段内的文件查询完毕(每次最多只能查询20条记录),pstInParam与pstOutParam内存由用户申请释放
        search target recognition result:nFilecount: need search item, return value is media file item return value<nFilecount then corresponding period file search complete(search max of 20 records each time)
        user malloc and free (pstInParam's and pstOutParam's) memory
        """
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_DoFindFaceRecognition(pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopFindFaceRecognition(cls, lFindHandle: int) -> C_BOOL:
        """
        结束查询
        end search
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_StopFindFaceRecognition(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ListenServer(cls, ip: str, port: c_ushort, nTimeout: int, cbListen: fServiceCallBack, dwUserData: C_LDWORD) -> C_BOOL:
        """
        主动注册功能,启动服务；nTimeout参数已无效(默认为设备断线后SDK内部登出); actively registration function. enable service. nTimeout is invalid.
        :param ip: 设备IP;device IP
        :param port:设备端口;device port
        :param nTimeout:等待时间;wait time
        :param cbListen:等待时间;wait time
        :param dwUserData:用户数据; User data
        :return:订阅句柄;Handle
        """
        ip = c_char_p(ip.encode())
        dwUserData = C_LDWORD(dwUserData)
        cls.sdk.CLIENT_ListenServer.restype = C_LLONG
        result = cls.sdk.CLIENT_ListenServer(ip, port, nTimeout, cbListen, dwUserData)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopListenServer(cls, lServerHandle: C_LLONG) -> bool:
        """
        停止服务; stop service
        :param lServerHandle: 服务ID,ListenServer返回值;service handle,ListenServer returns value
        :return:result: 1：success,0:failed
        """
        result = cls.sdk.CLIENT_StopListenServer(lServerHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetWaterDataStatServerCaps(cls, lLoginID: int, pstuInParam: NET_IN_WATERDATA_STAT_SERVER_GETCAPS_INFO, pstuOutParam: NET_OUT_WATERDATA_STAT_SERVER_GETCAPS_INFO, nWaitTime: int) -> C_LLONG:
        """
        获取水质检测能力
        Acquire water quality detection capability
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数; [in] pstuInParam Interface input parameters
        :param pstuOutParam: [out]pstuOutParam 接口输出参数; [out]pstuOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_GetWaterDataStatServerCaps.restype = C_LLONG
        result = cls.sdk.CLIENT_GetWaterDataStatServerCaps(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetWaterDataStatServerWaterData(cls, lLoginID: int, pstuInParam: NET_IN_WATERDATA_STAT_SERVER_GETDATA_INFO, pstuOutParam: NET_OUT_WATERDATA_STAT_SERVER_GETDATA_INFO, nWaitTime: int) -> C_LLONG:
        """
        水质检测实时数据获取
        Real time data acquisition of water quality detection
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数; [in] pstuInParam Interface input parameters
        :param pstuOutParam: [out]pstuOutParam 接口输出参数; [out]pstuOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_GetWaterDataStatServerWaterData.restype = C_LLONG
        result = cls.sdk.CLIENT_GetWaterDataStatServerWaterData(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindWaterDataStatServer(cls, lLoginID: int, pstuInParam: NET_IN_START_FIND_WATERDATA_STAT_SERVER_INFO, pstuOutParam: NET_OUT_START_FIND_WATERDATA_STAT_SERVER_INFO, nWaitTime: int) -> C_LLONG:
        """
        开始水质检测报表数据查询
        Start data query of water quality test report
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数; [in] pstuInParam Interface input parameters
        :param pstuOutParam: [out]pstuOutParam 接口输出参数; [out]pstuOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_StartFindWaterDataStatServer.restype = C_LLONG
        result = cls.sdk.CLIENT_StartFindWaterDataStatServer(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindWaterDataStatServer(cls, lLoginID: int, pstuInParam: NET_IN_DO_FIND_WATERDATA_STAT_SERVER_INFO, pstuOutParam: NET_OUT_DO_FIND_WATERDATA_STAT_SERVER_INFO, nWaitTime: int) -> C_LLONG:
        """
        水质检测报表数据查询
        Data query of water quality test report
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数; [in] pstuInParam Interface input parameters
        :param pstuOutParam: [out]pstuOutParam 接口输出参数; [out]pstuOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_DoFindWaterDataStatServer.restype = C_LLONG
        result = cls.sdk.CLIENT_DoFindWaterDataStatServer(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopFindWaterDataStatServer(cls, lLoginID: int, pstuInParam: NET_IN_STOP_FIND_WATERDATA_STAT_SERVER_INFO, pstuOutParam: NET_OUT_STOP_FIND_WATERDATA_STAT_SERVER_INFO, nWaitTime: int) -> C_LLONG:
        """
        停止水质检测报表数据查询
        Stop data query of water quality test report
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数; [in] pstuInParam Interface input parameters
        :param pstuOutParam: [out]pstuOutParam 接口输出参数; [out]pstuOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_StopFindWaterDataStatServer.restype = C_LLONG
        result = cls.sdk.CLIENT_StopFindWaterDataStatServer(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceInfoOpreate(cls, lLoginID: int, emType: EM_FACEINFO_OPREATE_TYPE, pInParam: c_void_p, pOutParam: c_void_p, nWaitTime: int) -> C_BOOL:
        """
        :人脸信息记录操作函数
        : CLIENT_FaceInfoOpreate
        the opreation function of face info
        :param lLoginID: [in]: LLONG :lLoginID  登陆句柄; [in]: LLONG :lLoginID  login handle
        :param emType: [in]: EM_FACEINFO_OPREATE_TYPE: emType 操作类型; [in]: EM_FACEINFO_OPREATE_TYPE: emType opreate type
        :param pInParam: [in]: void* :pInParam  接口输入参数, 资源由用户维护; [in]: void* :pInParam  the input param, the resource is maintained by user
        :param pOutParam: [out]: void* :pOutParam  接口输出参数, 资源由用户维护; [out]: void* :pOutParam  the outtime param, the resource is maintained by user
        :param nWaitTime: [in]: int :nWaitTime  等待超时时间; [in]: int :nWaitTime  timeout
        :return: : BOOL; : BOOL
        """
        lLoginID = C_LLONG(lLoginID)
        emType = C_ENUM(emType)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceInfoOpreate(lLoginID, emType, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDeviceType(cls, lLoginID: int, pstInParam: NET_IN_GET_DEVICETYPE_INFO, pstOutParam: NET_OUT_GET_DEVICETYPE_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取设备类型
        Get Device Type(not the true type of the device)
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetDeviceType(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDeviceAllInfo(cls, lLoginID: int, pstInParam: NET_IN_GET_DEVICE_AII_INFO, pstOutParam: NET_OUT_GET_DEVICE_AII_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取IPC设备的存储信息
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetDeviceAllInfo(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetUnifiedStatus(cls, lLoginID: int, pInParam: NET_IN_UNIFIEDINFOCOLLECT_GET_DEVSTATUS, pOutParam: NET_OUT_UNIFIEDINFOCOLLECT_GET_DEVSTATUS, nWaitTime: int) -> C_BOOL:
        """
        获取设备状态, DMSS专用接口, pInParam与pOutParam内存由用户申请释放
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetUnifiedStatus(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindNumberStat(cls, lLoginID: int, pstInParam: NET_IN_FINDNUMBERSTAT, pstOutParam: NET_OUT_FINDNUMBERSTAT) -> C_LLONG:
        """
        开始查询视频统计信息,pstInParam与pstOutParam内存由用户申请释放
        start find number state,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        cls.sdk.CLIENT_StartFindNumberStat.restype = C_LLONG
        result = cls.sdk.CLIENT_StartFindNumberStat(lLoginID, pstInParam, pstOutParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindNumberStat(cls, lFindHandle: int, pstInParam: NET_IN_DOFINDNUMBERSTAT, pstOutParam: NET_OUT_DOFINDNUMBERSTAT) -> c_int:
        """
        继续查询视频统计,pstInParam与pstOutParam内存由用户申请释放
        do find number state,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lFindHandle = C_LLONG(lFindHandle)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        result = cls.sdk.CLIENT_DoFindNumberStat(lFindHandle, pstInParam, pstOutParam)
        return result

    @classmethod
    def StopFindNumberStat(cls, lFindHandle: int) -> C_BOOL:
        """
        结束查询视频统计
        stop find number state
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_StopFindNumberStat(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDeviceInfo(cls, lLoginID: int, pInParam: NET_IN_GET_DEVICE_LIST_INFO, pOutParam: NET_OUT_GET_DEVICE_LIST_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取已添加的设备状态
        interface of get added device info
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetDeviceInfo(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetChannelInfo(cls, lLoginID: int, pInParam: NET_IN_GET_CHANNEL_INFO, pOutParam: NET_OUT_GET_CHANNEL_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取设备通道信息
        interface of get channel info
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetChannelInfo(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def BatchAppendFaceRecognition(cls, lLoginID: int, pstInParam: NET_IN_BATCH_APPEND_FACERECONGNITION, pstOutParam: NET_OUT_BATCH_APPEND_FACERECONGNITION, nWaitTime: int) -> C_BOOL:
        """
        添加多个人员信息和人脸样本
        batch append persons, user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_BatchAppendFaceRecognition(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindFaceRecognition(cls, lLoginID: int, pstInParam: NET_IN_STARTFIND_FACERECONGNITION, pstOutParam: NET_OUT_STARTFIND_FACERECONGNITION, nWaitTime: int) -> C_BOOL:
        """
        按条件查询目标识别结果 ,pstInParam与pstOutParam内存由用户申请释放
        by filter search Target recognition result ,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_StartFindFaceRecognition(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceRecognitionPutDisposition(cls, lLoginID: int, pstInParam: NET_IN_FACE_RECOGNITION_PUT_DISPOSITION_INFO, pstOutParam: NET_OUT_FACE_RECOGNITION_PUT_DISPOSITION_INFO, nWaitTime: int) -> C_BOOL:
        """
        以人脸库的角度进行布控, pstInParam与pstOutParam内存由用户申请释放
        put disposition to Target recognition, user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceRecognitionPutDisposition(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceRecognitionDelDisposition(cls, lLoginID: int, pstInParam: NET_IN_FACE_RECOGNITION_DEL_DISPOSITION_INFO, pstOutParam: NET_OUT_FACE_RECOGNITION_DEL_DISPOSITION_INFO, nWaitTime: int) -> C_BOOL:
        """
        以人脸库的角度进行撤控, pstInParam与pstOutParam内存由用户申请释放
        delete disposition from Target recognition, user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceRecognitionDelDisposition(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachAddFileState(cls, lLoginID: int, pstInParam: NET_IN_ADDFILE_STATE, pstOutParam: NET_OUT_ADDFILE_STATE, nWaitTime: int) -> C_LLONG:
        """
        订阅添加文件信息状态,pstInParam与pstOutParam内存由用户申请释放
        attach add file state,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachAddFileState.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachAddFileState(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceRServerGetDetectToken(cls, lLoginID: int, pInParam: NET_IN_FACERSERVER_GETDETEVTTOKEN, pOutParam: NET_OUT_FACERSERVER_GETDETEVTTOKEN, nWaitTime: int) -> C_BOOL:
        """
        获取人脸检测令牌
        Get face detection token
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pInParam: [in] pInParam 接口输入参数; [in] pInParam Interface input parameters
        :param pOutParam: [out]pOutParam 接口输出参数; [out] pOutParam Interface output parameters
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout in milliseconds
        :return: TRUE表示成功 FALSE表示失败; True indicates success and false indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceRServerGetDetectToken(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachDetectMultiFaceState(cls, lLoginID: int, pstInParam: NET_IN_MULTIFACE_DETECT_STATE, pstOutParam: NET_OUT_MULTIFACE_DETECT_STATE, nWaitTime: int) -> C_LLONG:
        """
        订阅大图检测小图进度,配合CLIENT_FaceRecognitionDetectMultiFace使用, pstInParam与pstOutParam内存由用户申请释放
        attach the progress of detect face images form the big images, cooperate with CLIENT_FaceRecognitionDetectMultiFace, user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachDetectMultiFaceState.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachDetectMultiFaceState(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def FaceRecognitionDetectMultiFace(cls, lLoginID: int, pstInParam: NET_IN_FACE_RECOGNITION_DETECT_MULTI_FACE_INFO, pstOutParam: NET_OUT_FACE_RECOGNITION_DETECT_MULTI_FACE_INFO, nWaitTime: int) -> C_BOOL:
        """
        向服务器提交多张大图，从中检测人脸图片, pstInParam与pstOutParam内存由用户申请释放
        submit multiple large images to the server, and detect face images from it, user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceRecognitionDetectMultiFace(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachDetectMultiFaceState(cls, lAttachHandle: int) -> C_BOOL:
        """
        取消订阅大图检测小图进度, lAttachHandle为CLIENT_AttachDetectMultiFaceState 返回的句柄
        detach the progress of detect face images form the big images, lAttachHandleis returned by CLIENT_AttachDetectMultiFaceState
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachDetectMultiFaceState(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartMultiFindFaceRecognitionEx(cls, lLoginID: int, pstuInParam: NET_IN_STARTMULTIFIND_FACERECONGNITION_EX, pstuOutParam: NET_OUT_STARTMULTIFIND_FACERECONGNITION_EX, nWaitTime: int) -> C_BOOL:
        """
        开始人脸检测/注册库的多通道查询
        Start multi-channel query of face detection/registration library
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID login handle
        :param pstuInParam: [in] pstuInParam 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam interface input parameters, memory resources are applied and released by the user
        :param pstuOutParam: [out]pstuOutParam 接口输出参数, 内存资源由用户申请和释放; [out]pstuOutParam interface output parameters, memory resources are applied and released by the user
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_StartMultiFindFaceRecognitionEx(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindFaceRecognitionEx(cls, pstuInParam: NET_IN_DOFIND_FACERECONGNITION_EX, pstuOutParam: NET_OUT_DOFIND_FACERECONGNITION_EX, nWaitTime: int) -> C_BOOL:
        """
        获取人脸查询结果信息
        Get face query result information
        :param pstuInParam: [in] pstuInParam 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam interface input parameters, memory resources are applied and released by the user
        :param pstuOutParam: [out]pstuOutParam 接口输出参数, 内存资源由用户申请和释放; [out]pstuOutParam interface output parameters, memory resources are applied and released by the user
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_DoFindFaceRecognitionEx(pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def Init(cls, cbDisConnect: fDisConnect, dwUser: int) -> C_BOOL:
        """
        SDK初始化
        SDK Initialization
        """
        dwUser = C_LDWORD(dwUser)
        result = cls.sdk.CLIENT_Init(cbDisConnect, dwUser)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetDeviceSerialNo(cls, lLoginID: int, pstInParam: NET_IN_GET_DEVICESERIALNO_INFO, pstOutParam: NET_OUT_GET_DEVICESERIALNO_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取设备序列号
        Get device serial number
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetDeviceSerialNo(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryDeviceLog(cls, lLoginID: int, pQueryParam: NET_A_QUERY_DEVICE_LOG_PARAM, pLogBuffer: c_char_p, nLogBufferLen: int, pRecLogNum: int, waittime: int) -> C_BOOL:
        """
        查询设备日志，以分页方式查询(pQueryParam, pLogBuffer内存由用户申请释放)
        Search device log page by page.
        """
        lLoginID = C_LLONG(lLoginID)
        pQueryParam = pointer(pQueryParam)
        nLogBufferLen = c_int(nLogBufferLen)
        pRecLogNum = pointer(c_int(pRecLogNum))
        waittime = c_int(waittime)
        result = cls.sdk.CLIENT_QueryDeviceLog(lLoginID, pQueryParam, pLogBuffer, nLogBufferLen, pRecLogNum, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachLowRateWPAN(cls, lLoginID: int, pstInParam: NET_IN_ATTACH_LOWRATEWPAN, pstOutParam: NET_OUT_ATTACH_LOWRATEWPAN, nWaitTime: int) -> C_LLONG:
        """
        订阅无线对码信息接口,pstInParam与pstOutParam内存由用户申请释放
        Order wireless code info port,user malloc memory of pstInBuf and pstOutBuf
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachLowRateWPAN.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachLowRateWPAN(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachLowRateWPAN(cls, lAttachHandle: int) -> C_BOOL:
        """
        取消订阅无线对码信息接口,lAttachHandle是CLIENT_AttachLowRateWPAN返回值
        Cancel order wireless info port, lAttachHandle is CLIENT_AttachLowRateWPAN return value
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachLowRateWPAN(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def TransmitCmd(cls, lLoginID: int, pstuInParam: NET_IN_TRANSMIT_CMD, pstuOutParam: NET_OUT_TRANSMIT_CMD, nWaitTime: int) -> C_BOOL:
        """
        RPC测试
        RPC test
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_TransmitCmd(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ManualTest(cls, lLoginID: int, pstuInParam: NET_IN_MANUAL_TEST, pstuOutParam: NET_OUT_MANUAL_TEST, nWaitTime: int) -> C_BOOL:
        """
        手动测试
        Manual test
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_ManualTest(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AddAlarmUser(cls, lLoginID: int, pstuInParam: NET_IN_ADD_ALARM_USER, pstuOutParam: NET_OUT_ADD_ALARM_USER, nWaitTime: int) -> C_BOOL:
        """
        添加报警用户
        Add alarm user
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_AddAlarmUser(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ModifyAlarmUser(cls, lLoginID: int, pstuInParam: NET_IN_MODIFY_ALARM_USER, pstuOutParam: NET_OUT_MODIFY_ALARM_USER, nWaitTime: int) -> C_BOOL:
        """
        修改报警用户
        Modify alarm user
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_ModifyAlarmUser(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ModifyAlarmUserPassword(cls, lLoginID: int, pstuInParam: NET_IN_MODIFY_ALARM_USER_PASSWORD, pstuOutParam: NET_OUT_MODIFY_ALARM_USER_PASSWORD, nWaitTime: int) -> C_BOOL:
        """
        修改报警用户密码
        Modify alarm user password
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_ModifyAlarmUserPassword(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DeleteAlarmUser(cls, lLoginID: int, pstuInParam: NET_IN_DELETE_ALARM_USER, pstuOutParam: NET_OUT_DELETE_ALARM_USER, nWaitTime: int) -> C_BOOL:
        """
        删除报警用户
        Delete alarm user
        :param lLoginID: [in] lLoginID: 登录句柄; [in] lLoginID Login handle
        :param pstuInParam: [in] pstuInParam: 接口输入参数, 内存资源由用户申请和释放; [in] pstuInParam Indicates the interface parameter
        :param pstuOutParam: [out] pstuOutParam: 接口输出参数, 内存资源由用户申请和释放; [out] pstuOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime: 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_DeleteAlarmUser(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryDeviceTimeEx(cls, lLoginID: int, pDeviceTime: NET_TIME_EX, waittime: int) -> C_BOOL:
        """
            查询设备当前时间扩展接口
            Search device current time extension interface
        """
        lLoginID = C_LLONG(lLoginID)
        pDeviceTime = pointer((pDeviceTime))
        waittime = c_int(waittime)
        result = cls.sdk.CLIENT_QueryDeviceTimeEx(lLoginID, pDeviceTime, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartTrafficFluxStat(cls, lLoginID: C_LLONG, pstInParam: NET_IN_TRAFFICFLUXSTAT, pstOutParam: NET_OUT_TRAFFICFLUXSTAT) -> C_LLONG:
        """
        交通流量统计,pstInParamg与pstOutParam内存由用户申请释放
        start traffic flux state,user malloc and free (pstInParam's and pstOutParam's) memory
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        cls.sdk.CLIENT_StartTrafficFluxStat.restype = C_LLONG
        result = cls.sdk.CLIENT_StartTrafficFluxStat(lLoginID, pstInParam, pstOutParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopTrafficFluxStat(cls, lFluxStatHandle: C_LLONG) -> C_BOOL:
        """
        结束流量统计
        stop traffic flux state
        """
        lFluxStatHandle = C_LLONG(lFluxStatHandle)
        result = cls.sdk.CLIENT_StopTrafficFluxStat(lFluxStatHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachTrafficFlowStatRealFlow(cls, lLoginID: int, pstuInParam: NET_IN_ATTACH_TRAFFIC_FLOW_STAT_REAL_FLOW, pstuOutParam: NET_OUT_ATTACH_TRAFFIC_FLOW_STAT_REAL_FLOW, nWaitTime: int) -> C_LLONG:
        """
        订阅交通流量统计
        Attach Traffic Flow Stat Real Flow
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID: Login handle
        :param pstuInParam: [in] pstInParam 接口输入参数; [in] pstInParam: Interface input parameters, memory resources are requested and released by the user
        :param pstuOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam: Interface output parameters, memory resources are requested and released by the user
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime: Interface timeout, in milliseconds
        :return: 返回订阅句柄; AttachHandle
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer((pstuInParam))
        pstuOutParam = pointer((pstuOutParam))
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachTrafficFlowStatRealFlow.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachTrafficFlowStatRealFlow(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachTrafficFlowStatRealFlow(cls, lAttachHandle: int) -> C_BOOL:
        """
        取消订阅交通流量统计
        detach Traffic Flow Stat Real Flow
        :param lAttachHandle: [in] lAttachHandle 订阅句柄; [in] lAttachHandle Attach Handle
        :return: TRUE表示成功 FALSE表示失败; TRUE means success, FALSE means failure
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachTrafficFlowStatRealFlow(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachCrowdDistriMap(cls, lLoginID: int, pstuInParam: NET_IN_ATTACH_TRAFFIC_FLOW_STAT_REAL_FLOW, pstuOutParam: NET_OUT_ATTACH_TRAFFIC_FLOW_STAT_REAL_FLOW, nWaitTime: int) -> C_LLONG:
        """
        订阅人群分布图实时统计信息
        Attach Crowd Distri Map
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID: Login handle
        :param pstuInParam: [in] pstInParam 接口输入参数; [in] pstInParam: Interface input parameters, memory resources are requested and released by the user
        :param pstuOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam: Interface output parameters, memory resources are requested and released by the user
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime: Interface timeout, in milliseconds
        :return: 返回订阅句柄; AttachHandle
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer((pstuInParam))
        pstuOutParam = pointer((pstuOutParam))
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachCrowdDistriMap.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachCrowdDistriMap(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachCrowdDistriMap(cls, lAttachHandle: int) -> C_BOOL:
        """
        取消订阅人群分布图实时统计信息
        detach Crowd Distri Map
        :param lAttachHandle: [in] lAttachHandle 订阅句柄; [in] lAttachHandle Attach Handle
        :return: TRUE表示成功 FALSE表示失败; TRUE means success, FALSE means failure
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachCrowdDistriMap(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindFluxStat(cls, lLoginID: int, pstInParam: NET_IN_TRAFFICSTARTFINDSTAT, pstOutParam: NET_OUT_TRAFFICSTARTFINDSTAT) -> C_LLONG:
        """
        获取流量统计信息,pstInParam与pstOutParam内存由用户申请释放
        start find flux state,user malloc and free (pstInParam's and pstOutParam's) memory
        :return: 处理句柄
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        cls.sdk.CLIENT_StartFindFluxStat.restype = C_LLONG
        result = cls.sdk.CLIENT_StartFindFluxStat(lLoginID, pstInParam, pstOutParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindFluxStat(cls, lFindHandle: int, pstInParam: NET_IN_TRAFFICDOFINDSTAT, pstOutParam: NET_OUT_TRAFFICDOFINDSTAT) -> c_int:
        """
        继续查询流量统计,pstInParam与pstOutParam内存由用户申请释放
        do find flux state,user malloc and free (pstInParam's and pstOutParam's) memory
        :return: 大于0表示成功
        """
        lFindHandle = C_LLONG(lFindHandle)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        result = cls.sdk.CLIENT_DoFindFluxStat(lFindHandle, pstInParam, pstOutParam)
        return result

    @classmethod
    def StopFindFluxStat(cls, lFindHandle: int) -> C_BOOL:
        """
        结束查询流量统计
        stop find flux state
        :return: TRUE表示成功 FALSE表示失败
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_StopFindFluxStat(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OpenDoor(cls, lLoginID: int, pInParam: NET_IN_FACE_OPEN_DOOR, pOutParam: NET_OUT_FACE_OPEN_DOOR, nWaitTime: int) -> C_BOOL:
        """
        远程认证开门（闸机）
        Remote authentication door opening (gate)
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID: Login handle
        :param pstuInParam: [in] pstInParam 接口输入参数; [in] pstInParam: Interface input parameters, memory resources are requested and released by the user
        :param pstuOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam: Interface output parameters, memory resources are requested and released by the user
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime: Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE means success, FALSE means failure
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_FaceOpenDoor(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def OperateAccessControlManager(cls, lLoginID: int, emtype: EM_A_NET_EM_ACCESS_CTL_MANAGER, pstInParam: c_void_p, pstOutParam: c_void_p, nWaitTime: int) -> C_BOOL:
        """
        门禁控制器操作接口
        interface of operate AccessControlManager
        :return: TRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        emtype = C_ENUM(emtype)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_OperateAccessControlManager(lLoginID, emtype, byref(pstInParam), byref(pstOutParam), nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SecurityExportDataEx(cls, lLoginID: int, pstInParam: NET_IN_SECURITY_EXPORT_DATA_INFO, pstOutParam: NET_OUT_SECURITY_EXPORT_DATA_INFO, nWaitTime: int) -> C_BOOL:
        """
        设备导出文件接口
        Interface for exporting files from the device
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstInParam: [in] pstInParam 接口输入参数; [in] pstInParam Indicates the interface parameter
        :param pstOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SecurityExportDataEx(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SecurityImportDataEx(cls, lLoginID: int, pstInParam: NET_IN_SECURITY_IMPORT_DATA_INFO, pstOutParam: NET_OUT_SECURITY_IMPORT_DATA_INFO, nWaitTime: int) -> C_BOOL:
        """
        设备导入文件接口
        Interface for importing device files
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstInParam: [in] pstInParam 接口输入参数; [in] pstInParam Indicates the interface parameter
        :param pstOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SecurityImportDataEx(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SecurityPrepareExportData(cls, lLoginID: int, pstInParam: NET_IN_SECURITY_PREPARE_EXPORT_DATA_INFO, pstOutParam: NET_OUT_SECURITY_PREPARE_EXPORT_DATA_INFO, nWaitTime: int) -> C_BOOL:
        """
        准备生成导出文件接口
        Prepares the interface for generating and exporting files
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstInParam: [in] pstInParam 接口输入参数; [in] pstInParam Indicates the interface parameter
        :param pstOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SecurityPrepareExportData(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SecurityGetCaps(cls, lLoginID: int, pstInParam: NET_IN_SECURITY_GETCAPS_INFO, pstOutParam: NET_OUT_SECURITY_GETCAPS_INFO, nWaitTime: int) -> C_BOOL:
        """
        查询特定数据类型的任务状态接口
        Interface for querying task status of a specific data type
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstInParam: [in] pstInParam 接口输入参数; [in] pstInParam Indicates the interface parameter
        :param pstOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SecurityGetCaps(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SecurityGetTaskStatus(cls, lLoginID: int, pstInParam: NET_IN_SECURITY_GET_TASK_STATUS_INFO, pstOutParam: NET_OUT_SECURITY_GET_TASK_STATUS_INFO, nWaitTime: int) -> C_BOOL:
        """
        查询当前支持的导入导出数据类型
        Queries the supported import and export data types
        :param lLoginID: [in] lLoginID 登录句柄; [in] lLoginID Login handle
        :param pstInParam: [in] pstInParam 接口输入参数; [in] pstInParam Indicates the interface parameter
        :param pstOutParam: [out] pstOutParam 接口输出参数; [out] pstOutParam Indicates the output parameter of the interface
        :param nWaitTime: [in] nWaitTime 接口超时时间, 单位毫秒; [in] nWaitTime Interface timeout, in milliseconds
        :return: TRUE表示成功 FALSE表示失败; TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer((pstInParam))
        pstOutParam = pointer((pstOutParam))
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SecurityGetTaskStatus(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def TransmitInfoForWeb(cls, lLoginID: int, szInBuffer: c_char_p, dwInBufferSize: int, szOutBuffer: c_char_p, dwOutBufferSize: int, pExtData: c_void_p, waittime: int) -> C_BOOL:
        """
        web info trasmit. This interface is invalid now, please use CLIENT_TransmitInfoForWebEx
        """
        lLoginID = C_LLONG(lLoginID)
        dwInBufferSize = C_DWORD(dwInBufferSize)
        dwOutBufferSize = C_DWORD(dwOutBufferSize)
        waittime = c_int(waittime)
        result = cls.sdk.CLIENT_TransmitInfoForWeb(lLoginID, szInBuffer, dwInBufferSize, szOutBuffer,
                                                   dwOutBufferSize, pExtData, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RadiometryGetRandomRegionTemper(cls, lLoginID: int, pInParam: NET_IN_RADIOMETRY_RANDOM_REGION_TEMPER, pOutParam: NET_OUT_RADIOMETRY_RANDOM_REGION_TEMPER, nWaitTime: int) -> C_BOOL:
        """
        获取测温区域的参数值, pInParam与pOutParam内存由用户申请释放
        Get the parameter value of the Temperature Monitoring area, user malloc and free memory of pInParam and pOutParam
        :return: TRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_RadiometryGetRandomRegionTemper(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def GetHeatMapsDirectly(cls, lLoginID: int, pInParam: NET_IN_GET_HEATMAPS_INFO, pOutParam: NET_OUT_GET_HEATMAPS_INFO, nWaitTime: int) -> C_BOOL:
        """
        获取热图数据
        heatmap data
        :return: TRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_GetHeatMapsDirectly(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def drcTable(cls, pGrayImg, nWidth: int, nHeight: int, yData, lut):
        """
    	处理图像,Processing images
        """
        cls.image_alg.drcTable(pGrayImg, nWidth, nHeight, 0, yData, lut)

    @classmethod
    def StartTalkByDataType(cls, lLoginID: int, pInParam: NET_IN_START_TALK_INFO, pOutParam: NET_OUT_START_TALK_INFO, nWaittime: int) -> C_LLONG:
        """
        打开语音对讲，这个接口可以从回调中得到音频裸数据，而CLIENT_StartTalkEx只能得到带音频头的数据
        Enable audio talk,this interface could get audio data with no head.
        :return: 对讲句柄
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaittime = c_int(nWaittime)
        cls.sdk.CLIENT_StartTalkByDataType.restype = C_LLONG
        result = cls.sdk.CLIENT_StartTalkByDataType(lLoginID, pInParam, pOutParam, nWaittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopTalkEx(cls, lTalkHandle: int) -> C_BOOL:
        """
        停止语音对讲
        Stop audio talk
        :return: TRUE表示成功 FALSE表示失败
        """
        lTalkHandle = C_LLONG(lTalkHandle)
        result = cls.sdk.CLIENT_StopTalkEx(lTalkHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def TalkSendDataByFile(cls, lTalkHandle: int, pInParam: NET_IN_TALK_SEND_DATA_FILE, pOutParam: NET_OUT_TALK_SEND_DATA_FILE) -> C_LLONG:
        """
        发送语音文件中的音频数据到设备
        send audio file to device
        success: return lTalkHandle
        fail: return 0
        :return: 成功返回 lTalkHandle， 失败返回 0
        """
        lTalkHandle = C_LLONG(lTalkHandle)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        cls.sdk.CLIENT_TalkSendDataByFile.restype = C_LLONG
        result = cls.sdk.CLIENT_TalkSendDataByFile(lTalkHandle, pInParam, pOutParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopTalkSendDataByFile(cls, lTalkHandle: int) -> C_BOOL:
        """
        停止发送音频文件
        stop send audio file to device
        :return: 成功返回 lTalkHandle， 失败返回 0
        """
        lTalkHandle = C_LLONG(lTalkHandle)
        result = cls.sdk.CLIENT_StopTalkSendDataByFile(lTalkHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def AttachIotboxComm(cls, lLoginID: C_LLONG, pstuInParam: NET_IN_ATTACH_IOTBOX_COMM, pstuOutParam: NET_OUT_ATTACH_IOTBOX_COMM, nWaitTime: c_int) -> C_LLONG:
        """
        订阅485实时数据;Subscribe to 485 real-time data
        :paramlLoginID 登录句柄;lLoginID Login handle
        :parampstuInParam 接口输入参数;pstuInParam Indicates the input parameter of the interface
        :parampstuOutParam 接口输出参数;pstuOutParam Indicates the output parameter of the interface
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Timeout period of the interface, in milliseconds
        :return返回订阅句柄;Returns the subscription handle
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_AttachIotboxComm.restype = C_LLONG
        result = cls.sdk.CLIENT_AttachIotboxComm(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DetachIotboxComm(cls, lAttachHandle: C_LLONG) -> C_BOOL:
        """
        取消订阅实时数据;Unsubscribe from real-time data
        :paramlAttachHandle 订阅句柄;lAttachHandle Subscription handle
        :returnTRUE表示成功 FALSE表示失败;TRUE indicates success. FALSE Indicates failure
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_DetachIotboxComm(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def CapturePictureEx2(cls, lPlayHandle: C_LLONG, pstInParam: NET_IN_CAPTURE_PICTURE, pstOutParam: NET_OUT_CAPTURE_PICTURE) -> C_BOOL:
        """
        手动抓图扩展接口(支持返回图片时间，精确到毫秒), hPlayHandle为预览或回放句柄;Extended Interface of snapshot(Support for returning picture time, accurate to milliseconds), hPlayHandle is monitor or playback handle
        :paramlPlayHandle 播放句柄
        :parampstInParam 接口输入参数, 内存资源由用户申请和释放
        :parampstOutParam 接口输出参数, 内存资源由用户申请和释放
        :returnTRUE表示成功 FALSE表示失败
        """
        lPlayHandle = C_LLONG(lPlayHandle)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        result = cls.sdk.CLIENT_CapturePictureEx2(lPlayHandle, pstInParam, pstOutParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetDecCallBackEx(cls, cbDecCallBack: fDecCallBack, dwUserData: C_LDWORD, emVideoStreamType: NET_VIDEOSTREAM_TYPE, nReserved: C_LLONG):
        """
        设置解码回调函数----扩展;set the call back function for decode of frame ---- extend
        :paramcbDecCallBack 解码回调函数
        :paramdwUserData  用户输入参数
        :paramemVideoStreamType  回调格式
        :paramnReserved  保留字段
        :returnTRUE表示成功 FALSE表示失败
        """
        cbDecCallBack = fDecCallBack(cbDecCallBack)
        dwUserData = C_LDWORD(dwUserData)
        emVideoStreamType = NET_VIDEOSTREAM_TYPE(emVideoStreamType)
        nReserved = C_LLONG(nReserved)
        cls.sdk.CLIENT_SetDecCallBackEx(cbDecCallBack, dwUserData, emVideoStreamType, nReserved)

    @classmethod
    def UploadRemoteFile(cls, lLoginID: C_LLONG, pInParam: NET_IN_UPLOAD_REMOTE_FILE, pOutParam: NET_OUT_UPLOAD_REMOTE_FILE, nWaitTime: c_int = 1000) -> C_BOOL:
        """
        同步文件上传, 只适用于小文件,pInParam与pOutParam内存由用户申请释放;sybcgribize fule upload,user malloc memory of pInParam and pOutParam
        :paramlLoginID 登录句柄
        :parampInParam 接口输入参数, 内存资源由用户申请和释放
        :parampOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :returnTRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_UploadRemoteFile(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def RebootDevice(cls, lLoginID: C_LLONG, pInParam: NET_IN_REBOOT_DEVICE, pOutParam: NET_OUT_REBOOT_DEVICE, nWaitTime: c_int) -> C_BOOL:
        """
        四合一烟感平台下发整机重启;The four in one smoke sensing platform sends out and the whole machine restarts
        :paramlLoginID 登录句柄
        :parampInParam 接口输入参数, 内存资源由用户申请和释放
        :parampOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :returnTRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_RebootDevice(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def InitDevAccess(cls, pInitAccessIn: NET_IN_INIT_DEVICE_ACCESS, pInitAccessOut: NET_OUT_INIT_DEVICE_ACCESS, dwWaitTime: C_DWORD, szLocalIp: c_char_p) -> C_BOOL:
        """
        开机向导流程，接入公网、在线升级检测等功能;boot wizard flow, include function netaccess, upgradecheck
        :parampInitAccessIn 接口输入参数, 内存资源由用户申请和释放
        :parampInitAccessOut 接口输出参数, 内存资源由用户申请和释放
        :paramdwWaitTime 接口超时时间, 单位毫秒
        :paramszLocalIp 本地ip
        :returnTRUE表示成功 FALSE表示失败
        """
        pInitAccessIn = pointer(pInitAccessIn)
        pInitAccessOut = pointer(pInitAccessOut)
        dwWaitTime = C_DWORD(dwWaitTime)
        szLocalIp = c_char_p(szLocalIp)
        result = cls.sdk.CLIENT_InitDevAccess(pInitAccessIn, pInitAccessOut, dwWaitTime, szLocalIp)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def ResetSystem(cls, lLoginID: C_LLONG, pstInParam: NET_IN_RESET_SYSTEM, pstOutParam: NET_OUT_RESET_SYSTEM, nWaitTime: c_int) -> C_BOOL:
        """
        重启系统,恢复出厂默认(包括清空配置和删除账户)并重启，实现硬复位功能;reset the system(clear user data and reboot to device init state)
        :paramlLoginID 登录句柄
        :parampstInParam 接口输入参数, 内存资源由用户申请和释放
        :parampstOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :returnTRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_ResetSystem(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def NormalRpcCallUsingJson(cls, lLoginID: C_LLONG, pstuInParam: NET_IN_NORMAL_RPCCALL_USING_JSON, pstuOutParam: NET_OUT_NORMAL_RPCCALL_USING_JSON, nWaitTime: c_int) -> C_BOOL:
        """
        通用RPC接口，支持Json传参;General RPC interface that supports JSON parameters
        :parampstuInParam 接口输入参数;pstuInParam Interface input parameters
        :parampstuOutParam 接口输出参数;pstuOutParam Interface output parameters
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Interface timeout time, in milliseconds
        :returnTRUE表示成功 FALSE表示失败;TRUE if successful, FALSE if failed
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_NormalRpcCallUsingJson(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindDetailNumberStatCluster(cls, lLoginID: C_LLONG, pstInParam: NET_IN_START_FIND_DETAIL_CLUSTER, pstOutParam: NET_OUT_START_FIND_DETAIL_CLUSTER, nWaitTime: c_int) -> C_BOOL:
        """
        区分报表查询, 单独实现一套全量查询数据接口;differentiates report query and implements a set of full query data interface separately
        :paramlLoginID 登录句柄;lLoginID Login handle
        :parampstInParam 接口输入参数;pstInParam Indicates the interface parameter
        :parampstOutParam 接口输出参数;pstOutParam Indicates the output parameter of the interface
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Interface timeout, in milliseconds
        :returnTRUE表示成功 FALSE表示失败;TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_StartFindDetailNumberStatCluster(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindDetailNumberStatCluster(cls, lLoginID: C_LLONG, pstInParam: NET_IN_DO_FIND_DETAIL_CLUSTER, pstOutParam: NET_OUT_DO_FIND_DETAIL_CLUSTER, nWaitTime: c_int) -> C_BOOL:
        """
        分批查询全量记录;Query full records in batches
        :paramlLoginID 登录句柄;lLoginID Login handle
        :parampstInParam 接口输入参数;pstInParam Indicates the interface parameter
        :parampstOutParam 接口输出参数;pstOutParam Indicates the output parameter of the interface
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Interface timeout, in milliseconds
        :returnTRUE表示成功 FALSE表示失败;TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_DoFindDetailNumberStatCluster(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopFindDetailNumberStatCluster(cls, lLoginID: C_LLONG, pstInParam: NET_IN_STOP_FIND_DETAIL_CLUSTER_INFO, pstOutParam: NET_OUT_STOP_FIND_DETAIL_CLUSTER_INFO, nWaitTime: c_int) -> C_BOOL:
        """
        停止查询;stop the query
        :paramlLoginID 登录句柄;lLoginID Login handle
        :parampstInParam 接口输入参数;pstInParam Indicates the interface parameter
        :parampstOutParam 接口输出参数;pstOutParam Indicates the output parameter of the interface
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Interface timeout, in milliseconds
        :returnTRUE表示成功 FALSE表示失败;TRUE indicates success. FALSE indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstInParam = pointer(pstInParam)
        pstOutParam = pointer(pstOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_StopFindDetailNumberStatCluster(lLoginID, pstInParam, pstOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def QueryRemotDevState(cls, lLoginID: C_LLONG, nType: c_int, nChannelID: c_int, pBuf: c_char_p, nBufLen: c_int, pRetLen: POINTER(c_int), waittime: c_int = 1000) -> C_BOOL:
        """
        查询远程设备状态,nType为DEVSTATE_ALARM_FRONTDISCONNECT时，通道号从1开始(pBuf内存由用户申请释放);query remote device state,when nType = DEVSTATE_ALARM_FRONTDISCONNECT,the number form 1.
        :paramlLoginID 登录句柄
        :paramnBufLen 根据nType类型确定相应结构体的大小
        :paramnChannelID 通道号
        :parampBuf 内存由用户申请释放,根据nType类型确定相应结构体
        :paramnBufLen 根据nType类型确定相应结构体的大小
        :parampRetLen 返回的数据长度
        :paramwaittime 接口超时时间, 单位毫秒
        :returnTRUE表示成功 FALSE表示失败
        """
        lLoginID = C_LLONG(lLoginID)
        nType = c_int(nType)
        nChannelID = c_int(nChannelID)
        pBuf = pointer(pBuf)
        nBufLen = c_int(nBufLen)
        pRetLen = POINTER(c_int)(pRetLen)
        waittime = c_int(waittime)
        result = cls.sdk.CLIENT_QueryRemotDevState(lLoginID, nType, nChannelID, pBuf, nBufLen, pRetLen, waittime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetOptimizeMode(cls, emType: EM_OPTIMIZE_TYPE, pParam: c_void_p) -> C_BOOL:
        """
        设置优化方案 pParam内存由用户申请释放，大小参照emType对应的结构体;Set optimize mode,user malloc and free pParam's memory,please refer to corresponding structure of emType
        :parampParam  pParam内存由用户申请释放，大小参照emType对应的结构体
        :parampParam  pParam内存由用户申请释放，大小参照emType对应的结构体
        :returnTRUE表示成功 FALSE表示失败
        """
        emType = EM_OPTIMIZE_TYPE(emType)
        pParam = c_void_p(pParam)
        result = cls.sdk.CLIENT_SetOptimizeMode(emType, pParam)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SCADAAttachInfo(cls, lLoginID: C_LLONG, pInParam: NET_IN_SCADA_ATTACH_INFO, pOutParam: NET_OUT_SCADA_ATTACH_INFO, nWaitTime: c_int) -> C_LLONG:
        """
        订阅监测点位信息,pInParam与pOutParam内存由用户申请释放;order monitor spot info,user malloc memory of pInParam and pOutParam
        :paramlLoginID 登录句柄
        :parampInParam 接口输入参数, 内存资源由用户申请和释放
        :parampOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :return返回处理句柄
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_SCADAAttachInfo.restype = C_LLONG
        result = cls.sdk.CLIENT_SCADAAttachInfo(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SCADADetachInfo(cls, lAttachHandle: C_LLONG) -> C_BOOL:
        """
        取消监测点位信息订阅;cancel monitor spot info order
        :paramlAttachHandle 处理句柄
        :returnTRUE表示成功 FALSE表示失败
        """
        lAttachHandle = C_LLONG(lAttachHandle)
        result = cls.sdk.CLIENT_SCADADetachInfo(lAttachHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StartFindSCADA(cls, lLoginID: C_LLONG, pInParam: NET_IN_SCADA_START_FIND, pOutParam: NET_OUT_SCADA_START_FIND, nWaitTime: c_int) -> C_LLONG:
        """
        开始查询SCADA点位历史数据,pInParam与pOutParam内存由用户申请释放;scada start find history info,user malloc memory of pInParam and pOutParam
        :paramlLoginID 登录句柄
        :parampInParam 接口输入参数, 内存资源由用户申请和释放
        :parampOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :return处理句柄
        """
        lLoginID = C_LLONG(lLoginID)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        cls.sdk.CLIENT_StartFindSCADA.restype = C_LLONG
        result = cls.sdk.CLIENT_StartFindSCADA(lLoginID, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def DoFindSCADA(cls, lFindHandle: C_LLONG, pInParam: NET_IN_SCADA_DO_FIND, pOutParam: NET_OUT_SCADA_DO_FIND, nWaitTime: c_int) -> C_BOOL:
        """
        获取SCADA点位历史数据,pInParam与pOutParam内存由用户申请释放;scada do find history info,user malloc memory of pInParam and pOutParam
        :paramlFindHandle 处理句柄
        :parampInParam 接口输入参数, 内存资源由用户申请和释放
        :parampOutParam 接口输出参数, 内存资源由用户申请和释放
        :paramnWaitTime 接口超时时间, 单位毫秒
        :returnTRUE表示成功 FALSE表示失败
        """
        lFindHandle = C_LLONG(lFindHandle)
        pInParam = pointer(pInParam)
        pOutParam = pointer(pOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_DoFindSCADA(lFindHandle, pInParam, pOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def StopFindSCADA(cls, lFindHandle: C_LLONG) -> C_BOOL:
        """
        停止查询SCADA点位历史数据;scada stop find history info
        :paramlFindHandle 处理句柄
        :returnTRUE表示成功 FALSE表示失败
        """
        lFindHandle = C_LLONG(lFindHandle)
        result = cls.sdk.CLIENT_StopFindSCADA(lFindHandle)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SnapFromRecord(cls, lLoginID: C_LLONG, pstuInParam: NET_IN_SNAP_FROM_RECORD, pstuOutParam: NET_OUT_SNAP_FROM_RECORD, nWaitTime: c_int) -> C_BOOL:
        """
        指定时间点从录像中抓图;Take a screenshot from the video at a specified time point
        :paramlLoginID 登录句柄;lLoginID Login handle
        :parampstuInParam 接口入参;pstuInParam Indicates the interface parameter
        :parampstuOutParam 接口出参;pstuOutParam Indicates the outgoing parameter of the interface
        :paramnWaitTime 接口超时时间, 单位毫秒;nWaitTime Timeout period of the interface, in milliseconds
        :returnTRUE表示成功 FALSE表示失败;TRUE Indicates success. FALSE Indicates failure
        """
        lLoginID = C_LLONG(lLoginID)
        pstuInParam = pointer(pstuInParam)
        pstuOutParam = pointer(pstuOutParam)
        nWaitTime = c_int(nWaitTime)
        result = cls.sdk.CLIENT_SnapFromRecord(lLoginID, pstuInParam, pstuOutParam, nWaitTime)
        if not result:
            print(cls.GetLastErrorMessage())
        return result

    @classmethod
    def SetPlayBackSpeedEx(cls, lPlayHandle: C_LLONG, dbSpeed: c_double) -> C_BOOL:
        """
        设置录像回放速度扩展，速度支持小数,不支持和CLIENT_FastPlayBack、CLIENT_SlowPlayBack配套使用，仅限单独使用，仅支持组件化设备;Set video playback speed extension, supports decimals, does not support pairing with CLIENT_SastPlayBack, CLIENT_SlowPlayBack, only for standalone use, only supports component-based devices
        :paramlPlayHandle: 播放句柄;lPlayHandle: Play handle
        :paramdbSpeed: 速度;dbSpeed: speed
        :returnTRUE表示成功 FALSE表示失败;TRUE indicates success, FALSE indicates failure
        """
        lPlayHandle = C_LLONG(lPlayHandle)
        dbSpeed = c_double(dbSpeed)
        result = cls.sdk.CLIENT_SetPlayBackSpeedEx(lPlayHandle, dbSpeed)
        if not result:
            print(cls.GetLastErrorMessage())
        return result



__all__ = ['NetSDK', ]
