# _*_ coding:utf-8 _*_

from enum import IntEnum


class EM_EVENT_IVS_TYPE(IntEnum):
    """
    智能事件类型, 在RealLoadPicture或fAnalyzerDataCallBack接口中使用; intelligent event type, used in RealLoadPicture or fAnalyzerDataCallBack
    """
    ALL = 0x00000001,                           # 订阅所有事件; subscription all event
    CROSSLINEDETECTION = 0x00000002,            # 警戒线事件(对应 DEV_EVENT_CROSSLINE_INFO);cross line event(Corresponding to DEV_EVENT_CROSSLINE_INFO)
    CROSSREGIONDETECTION = 0x00000003,          # 警戒区事件(对应 DEV_EVENT_CROSSREGION_INFO);cross region event(Corresponding to DEV_EVENT_CROSSREGION_INFO)
    STAYDETECTION = 0x00000006,                 # 停留事件(对应NET_A_DEV_EVENT_STAY_INFO);Stay Event(Corresponding to NET_A_DEV_EVENT_STAY_INFO)
    WANDERDETECTION = 0x00000007,               # 徘徊事件(对应NET_A_DEV_EVENT_WANDER_INFO); Wandering Event(Corresponding to NET_A_DEV_EVENT_WANDER_INFO)
    MOVEDETECTION = 0x00000009,                 # 移动事件(对应 DEV_EVENT_MOVE_INFO);move event(Corresponding to DEV_EVENT_MOVE_INFO)
    FIREDETECTION = 0x0000000C,                 # 火警事件(对应 NET_A_DEV_EVENT_FIRE_INFO);fire event(Corresponding to NET_A_DEV_EVENT_FIRE_INFO)
    SMOKEDETECTION = 0x0000000D,                # 烟雾报警事件(对应 NET_A_DEV_EVENT_SMOKE_INFO);smoke event(Corresponding to NET_A_DEV_EVENT_SMOKE_INFO)
    FIGHTDETECTION = 0x0000000E,                # 斗殴事件(对应 DEV_EVENT_FIGHT_INFO);fight event(Corresponding to DEV_EVENT_FIGHT_INFO)
    NUMBERSTAT = 0x00000010,                    # 数量统计事件(对应NET_A_DEV_EVENT_NUMBERSTAT_INFO);Person Count Event(Corresponding to NET_A_DEV_EVENT_NUMBERSTAT_INFO)
    TRAFFICCONTROL = 0x00000015,                # 交通管理事件(对应 NET_A_DEV_EVENT_TRAFFICCONTROL_INFO);traffic control event(Corresponding to NET_A_DEV_EVENT_TRAFFICCONTROL_INFO)
    TRAFFICACCIDENT = 0x00000016,               # 交通事故事件(对应 NET_A_DEV_EVENT_TRAFFICACCIDENT_INFO);traffic accident event(Corresponding to NET_A_DEV_EVENT_TRAFFICACCIDENT_INFO)
    TRAFFICJUNCTION = 0x00000017,               # 交通路口事件(对应 DEV_EVENT_TRAFFICJUNCTION_INFO);traffic junction event(Corresponding to DEV_EVENT_TRAFFICJUNCTION_INFO)
    TRAFFICGATE = 0x00000018,                   # 交通卡口事件(对应 NET_A_DEV_EVENT_TRAFFICGATE_INFO);traffic gate event(Corresponding to NET_A_DEV_EVENT_TRAFFICGATE_INFO)
    TRAFFICSNAPSHOT = 0x00000019,               # 交通抓拍事件(对应 NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO);traffic snapshot(Corresponding to NET_A_DEV_EVENT_TRAFFICSNAPSHOT_INFO)
    FACEDETECT = 0x0000001A,                    # 人脸检测事件(对应 DEV_EVENT_FACEDETECT_INFO); face detection(Corresponding to DEV_EVENT_FACEDETECT_INFO)
    TRAFFICJAM = 0x0000001B,                    # 交通拥堵事件(对应 NET_A_DEV_EVENT_TRAFFICJAM_INFO);TrafficJam detection, corresponding to NET_A_DEV_EVENT_TRAFFICJAM_INFO
    TRAFFIC_NONMOTORINMOTORROUTE = 0x0000001C,  # 非机动车占机动车车道事件(对应 NET_A_DEV_EVENT_TRAFFIC_NONMOTORINMOTORROUTE_INFO);Non-motor vehicles occupy the lanes(Corresponding to NET_A_DEV_EVENT_TRAFFIC_NONMOTORINMOTORROUTE_INFO)
    TRAFFIC_RUNREDLIGHT = 0x00000100,           # 交通违章-闯红灯事件(对应 NET_A_DEV_EVENT_TRAFFIC_RUNREDLIGHT_INFO);traffic-RunRedLight(Corresponding to NET_A_DEV_EVENT_TRAFFIC_RUNREDLIGHT_INFO)
    TRAFFIC_OVERLINE = 0x00000101,              # 交通违章-压车道线事件(对应 NET_A_DEV_EVENT_TRAFFIC_OVERLINE_INFO);traffic-Overline(Corresponding to NET_A_DEV_EVENT_TRAFFIC_OVERLINE_INFO)
    TRAFFIC_RETROGRADE = 0x00000102,            # 交通违章-逆行事件(对应 NET_A_DEV_EVENT_TRAFFIC_RETROGRADE_INFO);traffic-Retrograde(Corresponding to NET_A_DEV_EVENT_TRAFFIC_RETROGRADE_INFO)
    TRAFFIC_TURNLEFT = 0x00000103,              # 交通违章-违章左转(对应 NET_A_DEV_EVENT_TRAFFIC_TURNLEFT_INFO);traffic-TurnLeft(Corresponding to NET_A_DEV_EVENT_TRAFFIC_TURNLEFT_INFO)
    TRAFFIC_TURNRIGHT = 0x00000104,             # 交通违章-违章右转(对应 NET_A_DEV_EVENT_TRAFFIC_TURNRIGHT_INFO);traffic-TurnRight(Corresponding to NET_A_DEV_EVENT_TRAFFIC_TURNRIGHT_INFO)
    TRAFFIC_UTURN = 0x00000105,                 # 交通违章-违章掉头(对应 NET_A_DEV_EVENT_TRAFFIC_UTURN_INFO);traffic-Uturn(Corresponding to NET_A_DEV_EVENT_TRAFFIC_UTURN_INFO)
    TRAFFIC_OVERSPEED = 0x00000106,             # 交通违章-超速(对应 NET_A_DEV_EVENT_TRAFFIC_OVERSPEED_INFO);traffic-Overspeed(Corresponding to NET_A_DEV_EVENT_TRAFFIC_OVERSPEED_INFO)
    TRAFFIC_UNDERSPEED = 0x00000107,            # 交通违章-低速(对应 NET_A_DEV_EVENT_TRAFFIC_UNDERSPEED_INFO);traffic-Underspeed(Corresponding to NET_A_DEV_EVENT_TRAFFIC_UNDERSPEED_INFO)
    TRAFFIC_PARKING = 0x00000108,               # 交通违章-违章停车(对应 NET_A_DEV_EVENT_TRAFFIC_PARKING_INFO);traffic-Parking(Corresponding to NET_A_DEV_EVENT_TRAFFIC_PARKING_INFO)
    TRAFFIC_WRONGROUTE = 0x00000109,            # 交通违章-不按车道行驶(对应 NET_A_DEV_EVENT_TRAFFIC_WRONGROUTE_INFO);traffic-WrongRoute(Corresponding to NET_A_DEV_EVENT_TRAFFIC_WRONGROUTE_INFO)
    TRAFFIC_CROSSLANE = 0x0000010A,             # 交通违章-违章变道(对应 NET_A_DEV_EVENT_TRAFFIC_CROSSLANE_INFO);traffic-CrossLane(Corresponding to NET_A_DEV_EVENT_TRAFFIC_CROSSLANE_INFO)
    TRAFFIC_OVERYELLOWLINE = 0x0000010B,        # 交通违章-压黄线 (对应 NET_A_DEV_EVENT_TRAFFIC_OVERYELLOWLINE_INFO);traffic-OverYellowLine(Corresponding to NET_A_DEV_EVENT_TRAFFIC_OVERYELLOWLINE_INFO)
    TRAFFIC_DRIVINGONSHOULDER = 0x0000010C,     # 交通违章-路肩行驶事件(对应 NET_A_DEV_EVENT_TRAFFIC_DRIVINGONSHOULDER_INFO);traffic-DrivingOnShoulder(Corresponding to NET_A_DEV_EVENT_TRAFFIC_DRIVINGONSHOULDER_INFO)
    TRAFFIC_YELLOWPLATEINLANE = 0x0000010E,     # 交通违章-黄牌车占道事件(对应 NET_A_DEV_EVENT_TRAFFIC_YELLOWPLATEINLANE_INFO);traffic-YellowPlateInLane(Corresponding to NET_A_DEV_EVENT_TRAFFIC_YELLOWPLATEINLANE_INFO)
    TRAFFIC_PEDESTRAINPRIORITY = 0x0000010F,    # 交通违章-礼让行人/斑马线行人优先事件(对应 NET_A_DEV_EVENT_TRAFFIC_PEDESTRAINPRIORITY_INFO);Traffic offense-Pedestral has higher priority at the  crosswalk(Corresponding to NET_A_DEV_EVENT_TRAFFIC_PEDESTRAINPRIORITY_INFO)
    TRAFFIC_NOPASSING = 0x00000111,             # 交通违章-禁止通行事件(对应 NET_A_DEV_EVENT_TRAFFIC_NOPASSING_INFO);no passing(Corresponding to NET_A_DEV_EVENT_TRAFFIC_NOPASSING_INFO)
    FACERECOGNITION = 0x00000117,               # 目标识别事件(对应NET_DEV_EVENT_FACERECOGNITION_INFO); target recognition(Corresponding to NET_DEV_EVENT_FACERECOGNITION_INFO)
    TRAFFIC_MANUALSNAP = 0x00000118,            # 交通手动抓拍事件(对应 DEV_EVENT_TRAFFIC_MANUALSNAP_INFO); Traffic manual capture event (corresponding to dev_event_traffic_manualsnap_info)
    TRAFFIC_FLOWSTATE = 0x00000119,             # 交通流量统计事件(对应 DEV_EVENT_TRAFFIC_FLOW_STATE);traffic flow state(Corresponding to DEV_EVENT_TRAFFIC_FLOW_STATE)
    TRAFFIC_BACKING = 0x00000125,               # 违章倒车事件(对应 NET_A_DEV_EVENT_IVS_TRAFFIC_BACKING_INFO);illegal astern(Corresponding to NET_A_DEV_EVENT_IVS_TRAFFIC_BACKING_INFO)
    TRAFFIC_PEDESTRAIN = 0x0000012D,            # 交通行人事件(对应 NET_A_DEV_EVENT_TRAFFIC_PEDESTRAIN_INFO);passerby(Corresponding to NET_A_DEV_EVENT_TRAFFIC_PEDESTRAIN_INFO)
    TRAFFIC_THROW = 0x0000012E,                 # 交通抛洒物品事件(对应 NET_A_DEV_EVENT_TRAFFIC_THROW_INFO);throw(Corresponding to NET_A_DEV_EVENT_TRAFFIC_THROW_INFO)
    TRAFFIC_DRIVER_SMOKING = 0x00000139,        # 驾驶员抽烟事件(对应 NET_A_DEV_EVENT_TRAFFIC_DRIVER_SMOKING); Driver smoking event (Corresponding to NET_A_DEV_EVENT_TRAFFIC_DRIVER_SMOKING)
    TRAFFIC_DRIVER_CALLING = 0x0000013A,        # 驾驶员打电话事件(对应 NET_A_DEV_EVENT_TRAFFIC_DRIVER_CALLING); Driver calling event (Corresponding to NET_A_DEV_EVENT_TRAFFIC_DRIVER_CALLING)
    VIDEOBLIND = 0x00000153,                    # 视频遮挡事件(对应 NET_A_DEV_EVENT_ALARM_VIDEOBLIND); Video occlusion event (Corresponding to NET_A_DEV_EVENT_ALARM_VIDEOBLIND)
    TUMBLE_DETECTION = 0x00000177,              # 倒地报警事件(对应NET_A_DEV_EVENT_ALARM_TUMBLE_DETECTION_INFO); Fall detection event (Corresponding to NET_A_DEV_EVENT_ALARM_TUMBLE_DETECTION_INFO)
    ACCESS_CTL = 0x00000204,                    # 门禁事件 (对应 DEV_EVENT_ACCESS_CTL_INFO); Acccess control events (Corresponding to DEV_EVENT_ACCESS_CTL_INFO)
    TRAFFIC_TIREDPHYSIOLOGICAL = 0x00000207,    # 生理疲劳驾驶事件(对应 NET_A_DEV_EVENT_TIREDPHYSIOLOGICAL_INFO); Physiological fatigue driving event (Corresponding to NET_A_DEV_EVENT_TIREDPHYSIOLOGICAL_INFO)
    TRAFFIC_TIREDLOWERHEAD = 0x0000020A,        # 开车低头报警事件(对应 NET_A_DEV_EVENT_TIREDLOWERHEAD_INFO); Start up low head alarm event (Corresponding to NET_A_DEV_EVENT_TIREDLOWERHEAD_INFO)
    TRAFFIC_DRIVERLOOKAROUND = 0x0000020B,      # 开车左顾右盼报警事件(对应 NET_A_DEV_EVENT_DRIVERLOOKAROUND_INFO);Driving left and right looking alarm events (Corresponding to NET_A_DEV_EVENT_DRIVERLOOKAROUND_INFO)
    TRAFFIC_DRIVERLEAVEPOST = 0x0000020C,       # 开车离岗报警事件(对应 NET_A_DEV_EVENT_DRIVERLEAVEPOST_INFO); Leaving post during driving alarm event (Corresponding to NET_A_DEV_EVENT_DRIVERLEAVEPOST_INFO)
    MAN_NUM_DETECTION = 0x0000020E,             # 立体视觉区域内人数统计事件(对应NET_A_DEV_EVENT_MANNUM_DETECTION_INFO)regional population statistics (Corresponding to NET_A_DEV_EVENT_MANNUM_DETECTION_INFO)
    TRAFFIC_DRIVERYAWN = 0x00000210,            # 开车打哈欠事件(对应 NET_A_DEV_EVENT_DRIVERYAWN_INFO); Yawning incident during driving (Corresponding to NET_A_DEV_EVENT_DRIVERYAWN_INFO)
    TRAFFIC_QUEUEJUMP = 0x0000021C,             # 车辆加塞事件(对应 NET_A_DEV_EVENT_TRAFFIC_QUEUEJUMP_INFO);Event of car jump a queue(Corresponding to NET_A_DEV_EVENT_TRAFFIC_QUEUEJUMP_INFO)
    CROWDDETECTION = 0x0000022C,                # 人群密度检测事件(对应结构体 DEV_EVENT_CROWD_DETECTION_INFO);Event of crowd detection(Corresponding to DEV_EVENT_CROWD_DETECTION_INFO)
    FIREWARNING = 0x00000245,                   # 火警事件(对应NET_A_DEV_EVENT_FIREWARNING_INFO);Fire incidents(Corresponding to NET_A_DEV_EVENT_FIREWARNING_INFO)
    SHOPPRESENCE = 0x00000246,                  # 商铺占道经营事件(对应 NET_A_DEV_EVENT_SHOPPRESENCE_INFO);Business incident of shops occupying roads(Corresponding to NET_A_DEV_EVENT_SHOPPRESENCE_INFO)
    SPILLEDMATERIAL_DETECTION = 0x00000248,     # 抛洒物检测事件(对应 NET_A_DEV_EVENT_SPILLEDMATERIAL_DETECTION_INFO);Event of spilled material detection(Corresponding to NET_A_DEV_EVENT_SPILLEDMATERIAL_DETECTION_INFO)
    TRAFFIC_NONMOTOR_WITHOUTSAFEHAT = 0x0000024C,    # 非机动车未戴安全帽事件 (对应 NET_A_DEV_EVENT_TRAFFIC_NONMOTOR_WITHOUTSAFEHAT_INFO);Event of non motorized vehicles not wearing safety helmets(Corresponding to NET_A_DEV_EVENT_TRAFFIC_NONMOTOR_WITHOUTSAFEHAT_INFO)
    FLOWBUSINESS = 0x0000024E,                  # 流动摊贩事件 (对应 NET_A_DEV_EVENT_FLOWBUSINESS_INFO);Mobile vendor incident(NET_A_DEV_EVENT_FLOWBUSINESS_INFO)
    DUSTBIN_OVER_FLOW = 0x00000260,             # 垃圾桶满溢检测事件 (对应 DEV_EVENT_DUSTBIN_OVER_FLOW_INFO);Event of Dustbin Overflow detection (Corresponding to DEV_EVENT_DUSTBIN_OVER_FLOW_INFO)
    CLASSROOM_BEHAVIOR = 0x0000026A,            # 课堂行为分析事件(对应 NET_A_DEV_EVENT_CLASSROOM_BEHAVIOR_INFO);Event of classroom behavior detection(Corresponding to DEV_EVENT_CLASSROOM_BEHAVIOR_INFO)
    WORKCLOTHES_DETECT = 0x0000026E,            # 工装(安全帽 / 工作服等)检测事件(对应NET_A_DEV_EVENT_WORKCLOTHES_DETECT_INFO);Detection incidents of work equipment(Corresponding to NET_A_DEV_EVENT_WORKCLOTHES_DETECT_INFO)
    TRAFFIC_ROAD_BLOCK = 0x00000271,            # 交通路障检测事件(对应 NET_A_DEV_EVENT_TRAFFIC_ROAD_BLOCK_INFO);Event of traffic road block(Corresponding to NET_A_DEV_EVENT_TRAFFIC_ROAD_BLOCK_INFO)
    TRAFFIC_ROAD_CONSTRUCTION = 0x00000272,     # 交通道路施工检测事件(对应 NET_A_DEV_EVENT_TRAFFIC_ROAD_CONSTRUCTION_INFO);Event of traffic road construction(Corresponding to NET_A_DEV_EVENT_TRAFFIC_ROAD_CONSTRUCTION_INFO)
    SMARTMOTION_HUMAN = 0x00000279,             # 智能视频移动侦测事件(人), (对应 DEV_EVENT_SMARTMOTION_HUMAN_INFO); Intelligent video motion detection event (person), (corresponding to DEV_EVENT_SMARTMOTION_HUMAN_INFO)
    CAR_DRIVING_IN_OUT = 0x0000027B,            # 车辆驶入驶出状态事件(对应 DEV_EVENT_CAR_DRIVING_IN_OUT_INFO);Event of car driving in or out(Corresponding to DEV_EVENT_CAR_DRIVING_IN_OUT_INFO)
    PARKINGSPACE_STATUS = 0x0000027C,           # 停车位状态事件(对应 DEV_EVENT_PARKINGSPACE_STATUS_INFO);Event of parking spcae status(Corresponding to DEV_EVENT_PARKINGSPACE_STATUS_INFO)
    ANIMAL_DETECTION = 0x00000286,              # 动物检测事件(对应 NET_A_DEV_EVENT_ANIMAL_DETECTION_INFO);Animal testing events,(corresponding to NET_A_DEV_EVENT_ANIMAL_DETECTION_INFO)
    RADAR_REGION_DETECTION = 0x00000295,        # 雷达警戒区检测事件(对应 NET_A_DEV_EVENT_RADAR_REGION_DETECTION_INFO); Event of Radar cross region detection(Corresponding to  NET_A_DEV_EVENT_RADAR_REGION_DETECTION_INFO)
    DREGS_UNCOVERED = 0x00000299,               # 渣土车未遮盖载货检测事件(对应 NET_A_DEV_EVENT_DREGS_UNCOVERED_INFO);Event of loading test not covered by muck truck(Corresponding to NET_A_DEV_EVENT_DREGS_UNCOVERED_INFO)
    ANATOMY_TEMP_DETECT = 0x00000303,           # 人体温智能检测事件(对应 DEV_EVENT_ANATOMY_TEMP_DETECT_INFO);Event of Intelligent detection of human body temperature(Corresponding to  DEV_EVENT_ANATOMY_TEMP_DETECT_INFO)
    NONMOTOR_ENTRYING = 0x0000030C,             # 非机动车进入电梯(对应 DEV_EVENT_NONMOTOR_ENTRYING_INFO);Event of non-motor vehicle access elevator(Corresponding to DEV_EVENT_NONMOTOR_ENTRYING_INFO)
    TRAFFIC_ROAD_ALERT = 0x0000030E,            # 道路安全预警(对应 NET_A_DEV_EVENT_TRAFFIC_ROAD_ALERT_INFO);Event of traffic traffic road alert(Corresponding to NET_A_DEV_EVENT_TRAFFIC_ROAD_ALERT_INFO)
    TRAFFIC_VEHICLE_IN_EMERGENCY_LANE = 0x00000311,    # 占用应急车道事件(对应 NET_A_DEV_EVENT_TRAFFIC_VEHICLE_IN_EMERGENCY_LANE_INFO );Event of vehicle in emergency lane (Corresponding to NET_A_DEV_EVENT_TRAFFIC_VEHICLE_IN_EMERGENCY_LANE_INFO )
    TRAFFIC_SPECIAL_VEHICLE_DETECT = 0x00000333,    # 特殊车辆检测 (对应 NET_A_DEV_EVENT_TRAFFIC_SPECIAL_VEHICLE_INFO );Event of special vehicle detect (Corresponding to NET_A_DEV_EVENT_TRAFFIC_SPECIAL_VEHICLE_INFO)
    TRAFFIC_NONMOTOR = 0x00000335,              # 交通非机动车事件检测, 智能服务器使用 ( NET_A_DEV_EVENT_TRAFFIC_NONMOTOR_INFO );Event of traffic nonmotor detector(Corresponding to NET_A_DEV_EVENT_TRAFFIC_NONMOTOR_INFO )
    TRAFFIC_BOARD = 0x00000336,                 # 交通违章上下客事件检测 (对应 NET_A_DEV_EVENT_TRAFFIC_BOARD_INFO );Event of traffic board detection (Corresponding to NET_A_DEV_EVENT_TRAFFIC_BOARD_INFO )
    TRAFFIC_VISIBILITY = 0x00000337,            # 交通能见度事件检测 (对应 NET_A_DEV_EVENT_TRAFFIC_VISIBILITY_INFO );Event of traffic visibility detection (Corresponding to NET_A_DEV_EVENT_TRAFFIC_VISIBILITY_INFO )
    TRAFFIC_VEHICLE_CLEANLINESS = 0x00000338,   # 交通车辆清洁度检测事件检测 (对应 NET_A_DEV_EVENT_TRAFFIC_VEHICLE_CLEANLINESS_INFO);Event of traffic vehicle cleanliness detection (Corresponding to NET_A_DEV_EVENT_TRAFFIC_VEHICLE_CLEANLINESS_INFO)
    TRAFFIC_SPEED_CHANGE_DETECTION = 0x0000034E,    # 交通变速检测事件(对应 NET_A_DEV_EVENT_TRAFFIC_SPEED_CHANGE_DETECTION_INFO );Traffic Speed Change Detection(Corresponding NET_A_DEV_EVENT_TRAFFIC_SPEED_CHANGE_DETECTION_INFO )
    CONVEYER_BELT_BULK = 0x00000351,            # 传送带大块异物检测事件(对应DEV_EVENT_CONVEYER_BELT_BULK_INFO );Large foreign body detection event of conveyer belt(Corresponding to DEV_EVENT_CONVEYER_BELT_BULK_INFO )
    HEAT_IMAGING_TEMPER = 0x0000035C,           # 热成像测温点温度异常报警事件(对应结构体 DEV_EVENT_HEAT_IMAGING_TEMPER_INFO);Thermal temperature abnormal event alarm(Corresponding to DEV_EVENT_HEAT_IMAGING_TEMPER_INFO)
    DIALRECOGNITION = 0x00000371,               # 仪表检测事件(对应 DEV_EVENT_DIALRECOGNITION_INFO); Instrument detection event (corresponding to DEV_EVENT_DIALRECOGNITION_INFO)
    ELECTRICFAULT_DETECT = 0x00000372,          # 仪表类缺陷检测事件(对应 DEV_EVENT_ELECTRICFAULTDETECT_INFO);Instrument defect detection event (corresponding to DEV_EVENT_ELECTRICFAULTDETECT_INFO)
    TRAFFIC_CHANGE_LANE_CONTINUES = 0x00000387, # 机动车连续变道违法事件(对应 NET_A_DEV_EVENT_TRAFFIC_CHANGE_LANE_CONTINUES_INFO);Traffic Change Lane Continues Event(corresponding to NET_A_DEV_EVENT_TRAFFIC_CHANGE_LANE_CONTINUES_INFO)
    OPEN_INTELLI = 0x0000039D,                  # 开放智能事件(对应 DEV_EVENT_OPEN_INTELLI_INFO); Open intelligent event (corresponding to dev_event_open_intelli_info)
    TRAFFIC_CROSSING_SPEEDY = 0x00000408,       # 斑马线不减速事件 (对应 NET_A_DEV_EVENT_TRAFFIC_CROSSING_SPEEDY_INFO);Zebra crossing non deceleration event (Corresponding to NET_A_DEV_EVENT_TRAFFIC_CROSSING_SPEEDY_INFO)
    TRAFFIC_LARGECAR_NO_STOP = 0x00000409,      # 大车右转不停车事件(对应 NET_A_DEV_EVENT_TRAFFIC_LARGECAR_NO_STOP_INFO);Event of crane turning right without stopping(Corresponding to NET_A_DEV_EVENT_TRAFFIC_LARGECAR_NO_STOP_INFO)
    TRAFFIC_TRUCK_OCCUPIED = 0x0000040B,        # 大车占道事件(对应 NET_A_DEV_EVENT_TRAFFIC_TRUCK_OCCUPIED_INFO);Truck occupation event(Corresponding to NET_A_DEV_EVENT_TRAFFIC_TRUCK_OCCUPIED_INFO)
    TRAFFIC_SERPENTINE_CHANGE_LANE = 0x0000040F,    # 蛇形变道事件(对应 NET_A_DEV_EVENT_TRAFFIC_SERPENTINE_CHANGE_LANE_INFO);Traffic Serpentine Change Lane event(Corresponding to NET_A_DEV_EVENT_TRAFFIC_SERPENTINE_CHANGE_LANE_INFO)
    TANK_CAPACITY_DETECTION = 0x00000412,       # 贮柜储量检测事件(对应 DEV_EVENT_IVS_TANK_CAPACITY_DETECTION_INFO);Tank Capacity Detection Event(Corresponding to DEV_EVENT_IVS_TANK_CAPACITY_DETECTION_INFO)
    TANK_DUMPING_DETECTION = 0x00000413,        # 周转箱倒料不干净检测事件(对应 DEV_EVENT_IVS_TANK_DUMPING_DETECTION_INFO);Tank Dumping Detection Event(Corresponding to DEV_EVENT_IVS_TANK_DUMPING_DETECTION_INFO)
    TANK_OVERFLOW_DETECTION = 0x00000414,       # 尘棒箱满溢检测事件(对应 DEV_EVENT_IVS_TANK_OVERFLOW_DETECTION_INFO);Tank Overflow Detection Event(Corresponding to DEV_EVENT_IVS_TANK_OVERFLOW_DETECTION_INFO)
    USERMANAGER_FOR_TWSDK = 0x00000441,         # 用户信息上报事件(对应 NET_DEV_EVENT_USERMANAGER_FOR_TWSDK_INFO);User information reporting event(corresponding to NET_DEV_EVENT_USERMANAGER_FOR_TWSDK_INFO)
    TIMECHANGE_FOR_TWSDK = 0x0000044F,          # 系统时间被修改报警事件(对应 NET_DEV_EVENT_TIMECHANGE_FOR_TWSDK_INFO)System time modified alarm event(Timewatch)(corresponding to NET_DEV_EVENT_TIMECHANGE_FOR_TWSDK_INFO)
    SAME_OBJECT_SEARCH_DETECT = 0x00000472,     # 按图索骥物品检测事件(对应 NET_DEV_EVENT_SAME_OBJECT_SEARCH_DETECT_INFO);Trace object detection events (corresponding NET_DEV_EVENT_SAME_OBJECT_SEARCH_DETECT_INFO)
    SAME_OBJECT_SEARCH_COUNT = 0x00000480,      # 按图索骥物品计数事件(对应 NET_DEV_EVENT_SAME_OBJECT_SEARCH_COUNT_INFO);Event for counting items based on the chart (corresponding to NET-DEV-EVENT_SAME_BBJECT_SEARCH_COUNT_INFO)

class EM_QUERY_DEV_INFO_TYPE(IntEnum):
    """
    查询设备信息, 在接口QueryDevInfo中使用; query device info, used in QueryDevInfo
    """
    STORAGE_INFOS = 0x02,                       # 查询设备的存储模块信息列表, pInBuf = NET_IN_STORAGE_DEV_INFOS *, pOutBuf = NET_OUT_STORAGE_DEV_INFOS *; search device storage info list, pInBuf=NET_IN_STORAGE_DEV_INFOS*, pOutBuf= NET_OUT_STORAGE_DEV_INFOS *
    POINT_TEMPER = 0x0c,                        # 查询测温点的参数值, pInBuf= NET_IN_RADIOMETRY_GETPOINTTEMPER*, pOutBuf= NET_OUT_RADIOMETRY_GETPOINTTEMPER *
                                                # Query the parameter value of the temperature point, pInBuf= NET_IN_RADIOMETRY_GETPOINTTEMPER*, pOutBuf= NET_OUT_RADIOMETRY_GETPOINTTEMPER *
    RADIOMETRY_TEMPER = 0x0d,                   # 查询测温项的参数值, pInBuf= NET_IN_RADIOMETRY_GETTEMPER*, pOutBuf= NET_OUT_RADIOMETRY_GETTEMPER *
                                                # Query the parameter value of the temperature item, pInBuf= NET_IN_RADIOMETRY_GETTEMPER*, pOutBuf= NET_OUT_RADIOMETRY_GETTEMPER *
    CAMERA_STATE = 0x0e,                        # 获取摄像机状态,pInBuf= NET_IN_GET_CAMERA_STATEINFO*, pOutBuf= NET_OUT_GET_CAMERA_STATEINFO *; query camera state, pInBuf= NET_IN_GET_CAMERA_STATEINFO*, pOutBuf= NET_OUT_GET_CAMERA_STATEINFO *
    WLAN_ACCESSPOINT = 0x19,                    # 查询无线网络接入点信息,pInBuf=NET_IN_WLAN_ACCESSPOINT* , pOutBuf=NET_OUT_WLAN_ACCESSPOINT*; query wlan access point info, pInBuf=NET_IN_WLAN_ACCESSPOINT* , pOutBuf=NET_OUT_WLAN_ACCESSPOINT*
    TRAFFIC_RADAR_GET_OBJECT_EX = 0x3d,         # 获取相机雷达物体目标信息, pInBuf = NET_IN_TRAFFIC_RADAR_GET_OBJECT_EX_INFO*,pOutBuf = NET_OUT_TRAFFIC_RADAR_GET_OBJECT_EX_INFO*
                                                # Get the target information of camera radar object, pInBuf = NET_IN_TRAFFIC_RADAR_GET_OBJECT_EX_INFO*,pOutBuf = NET_OUT_TRAFFIC_RADAR_GET_OBJECT_EX_INFO*
    QUERY_PTZBASE_GET_FOCUS_VALUE = 0x3e,       # 获取镜头焦距参数,pInBuf=NET_IN_PTZBASE_GET_FOCUS_VALUE* , pOutBuf=NET_OUT_PTZBASE_GET_FOCUS_VALUE*; Get lens focal length parameter, pInBuf=NET_IN_PTZBASE_GET_FOCUS_VALUE* , pOutBuf=NET_OUT_PTZBASE_GET_FOCUS_VALUE*

class EM_QUERY_DEV_STATE_TYPE(IntEnum):
    """
    查询设备状态, 在接口QueryDevState中使用; query device state, used in QueryDevState
    """
    RECORDING = 0x0003,                         # 查询录象状态; Query video status
    DISK = 0x0004,                              # 查询硬盘信息,对应结构体为SDK_Struct.py内的SDK_HARDDISK_STATE;Search HDD information,(Corresponding to SDK_HARDDISK_STATE)
    SOFTWARE = 0x000F,                          # 查询设备软件版本信息, 对应结构体 NET_A_DEV_VERSION_INFO; Query device software version information, Corresponding to NET_A_DEV_VERSION_INFO
    ONLINE = 0x0035,                            # 查询设备的在线状态(返回一个DWORD, 1表示在线, 0表示断线); Query the online status of the equipment (return a DWORD, 1 means online, 0 means disconnected)
    PTZ_LOCATION = 0x0036,                      # 查询云台状态信息(对应结构体 SDK_PTZ_LOCATION_INFO); Query ptz state(struct SDK_PTZ_LOCATION_INFO)
    PTZ_VIEW_RANGE = 0x0051,                    # 查询云台可视域状态(对应 NET_A_OUT_PTZ_VIEW_RANGE_STATUS); Example Query the viewable status of the cloud head(corresponding to NET_A_OUT_PTZ_VIEW_RANGE_STATUS)
    SCADA_INFO = 0x156a,                        # 获取监测点位信息(对应 NET_SCADA_INFO);Get monitor spot info(corresponding to NET_SCADA_INFO)
    SCADA_INFO_BY_ID = 0x1570,                  # 通过设备、获取监测点位信息(对应 NET_SCADA_INFO_BY_ID);query point info by device id(corresponding to NET_SCADA_INFO_BY_ID)
    SCADA_DEVICE_LIST = 0x1571,                 # 获取当前主机所接入的外部设备ID(对应 NET_SCADA_DEVICE_LIST);query scada device id(corresponding to NET_SCADA_DEVICE_LIST)
    GET_ACCESSORY_INFO = 0x157e,                # 获取配件信息(对应 NET_GET_ACCESSORY_INFO); get accessory info(corresponding to NET_GET_ACCESSORY_INFO)

class CFG_CMD_TYPE:
    """
    配置命令,对应GetNewDevConfig和SetNewDevConfig接口;Configuration Command,corresponding to GetNewDevConfig and SetNewDevConfig interface
    """
    VIDEOWIDGET = "VideoWidget"                 # 视频编码物件配置(对应 AV_CFG_VideoWidget);Video widget configuration (Corresponding of AV_CFG_VideoWidget)
    LIGHTING = "Lighting"                       # 灯光设置(对应 CFG_LIGHTING_INFO); Configuration of lighting(Corresponding of CFG_LIGHTING_INFO)
    VIDEOINOPTIONS = "VideoInOptions"           # 视频输入前端选项(对应 CFG_VIDEO_IN_OPTIONS);Video input front-end options(Corresponding of CFG_VIDEO_IN_OPTIONS)
    THERMO_GRAPHY = "ThermographyOptions"       # 热成像摄像头属性配置(CFG_THERMOGRAPHY_INFO); Thermal imaging camera property configuration (CFG_THERMOGRAPHY_INFO)
    NTP = "NTP"                                 # 时间同步服务器(对应 CFG_NTP_INFO); Time synchronization server (corresponding to CFG_NTP_INFO)
    SNAP = "Snap"                               # 抓图配置(对应 NET_A_CFG_SNAP_INFO); Snapshot Configuration (Corresponding NET_A_CFG_SNAP_INFO)
    WLAN = "WLan"                               # WLAN配置(对应 NET_A_CFG_NETAPP_WLAN); configuration of WLAN(corresponding to NET_A_CFG_NETAPP_WLAN)
    DVRIP = "DVRIP"                             # 网络协议配置(对应 NET_A_CFG_DVRIP_INFO); DVRIP(Corresponding of NET_A_CFG_DVRIP_INFO)
    RECORD = "Record"                           # 定时录像配置(对应 NET_A_CFG_RECORD_INFO); Schedule record setup (corresponding to NET_A_CFG_RECORD_INFO)
    CHANNELTITLE = "ChannelTitle"               # 通道名称(对应 AV_CFG_ChannelName); Channel name (corresponding to AV_CFG_ChannelName)
    CMD_ENCODE = "Encode"                       # 图像通道属性配置(对应 CFG_ENCODE_INFO); Image channel attribute configuration (corresponding to cfg_encode_info)
    NETWORK = "Network"                         # 网络配置(对应 CFG_NETWORK_INFO); Network configuration (corresponding to cfg_network_info)
    THERMOMETRY_RULE = "ThermometryRule"        # 热成像测温规则配置(CFG_RADIOMETRY_RULE_INFO); Thermal imaging temperature rule configuration (CFG_RADIOMETRY_RULE_INFO)
    THERMOMETRY = "HeatImagingThermometry"      # 热成像测温全局配置(NET_A_CFG_THERMOMETRY_INFO); Thermal imaging Temperature Monitoring global config(NET_A_CFG_THERMOMETRY_INFO)
    STORAGENOEXIST = "StorageNotExist"          # 无存储设备报警配置(对应 NET_A_CFG_STORAGENOEXIST_INFO); No storage device alarm setup (corresponding to NET_A_CFG_STORAGENOEXIST_INFO)
    NETABORT = "NetAbort"                       # 网络断开报警配置(对应 NET_A_CFG_NETABORT_INFO); Network disconnection alarm setup (corresponding to NET_A_CFG_NETABORT_INFO)
    IPCONFLICT = "IPConflict"                   # IP冲突报警配置(对应 NET_A_CFG_IPCONFLICT_INFO); IP conflict alarm setup (corresponding to NET_A_CFG_IPCONFLICT_INFO)
    MACCONFLICT = "MacConflict"                 # MAC冲突报警配置(NET_A_CFG_MACCONFLICT_INFO); MAC conflict alarm config(NET_A_CFG_MACCONFLICT_INFO)
    LOGIN_FAILURE_ALARM = "LoginFailureAlarm"   # 登陆失败报警配置(对应结构体 NET_A_CFG_LOGIN_FAILURE_ALARM); configuration of login failure alarm(Corresponding to NET_A_CFG_LOGIN_FAILURE_ALARM)
    BATTERY_LOW_POWER = "BatteryLowPowerAlarm"  # 电池电量低配置(NET_A_CFG_BATTERY_LOW_POWER_INFO); Battery Power Min Config(NET_A_CFG_BATTERY_LOW_POWER_INFO)
    MOTIONDETECT = "MotionDetect"               # 动态检测报警配置(对应 NET_A_CFG_MOTION_INFO); Motion detect alarm setup (corresponding to NET_A_CFG_MOTION_INFO)
    ALARMINPUT = "Alarm"                        # 外部输入报警配置(对应 NET_A_CFG_ALARMIN_INFO); External input alarm setup(corresponding to NET_A_CFG_ALARMIN_INFO)
    STORAGEGROUP = "StorageGroup"               # 存储组信息(对应 NET_A_AV_CFG_StorageGroup 数组, 通道无关); Storage group info. Does not support (Corresponding of NET_A_AV_CFG_StorageGroup array , has no relationship with channel),
    RECORDMODE = "RecordMode"                   # 录像模式(对应 NET_A_AV_CFG_RecordMode); Record mode (Corresponding of NET_A_AV_CFG_RecordMode)
    ALARM_SUBSYSTEM = "AlarmSubSystem"          # 报警子系统配置(NET_A_CFG_ALARM_SUBSYSTEM_INFO); Alarm SubConfig(NET_A_CFG_ALARM_SUBSYSTEM_INFO)
    DEV_GENERRAL = "General"                    # 普通配置 (对应 NET_A_CFG_DEV_DISPOSITION_INFO); General configuration (corresponding  NET_A_CFG_DEV_DISPOSITION_INFO)
    SCENE_MODE = "SceneMode"                    # 情景模式(对应结构体 NET_A_CFG_SCENE_MODE_INFO); configuration of the scene mode (corresponding to NET_A_CFG_SCENE_MODE_INFO)
    CHASSISINTRUSION = "ChassisIntrusion"       # 机箱入侵报警(防拆报警)配置(NET_A_CFG_CHASSISINTRUSION_INFO); Chassis Intrusion Alarm(Tamper Alarm) Configuration(NET_A_CFG_CHASSISINTRUSION_INFO)
    WIRELESS = "Wireless"                       # 无线网络连接设置(对应 NET_A_CFG_WIRELESS_INFO); Wi-Fi Settings(Corresponding NET_A_CFG_WIRELESS_INFO)
    RAINBRUSH = "RainBrush"                     # 雨刷配置(对应 NET_A_CFG_RAINBRUSH_INFO) ; Rain brush(corresponding struct NET_A_CFG_RAINBRUSH_INFO)
    RAINBRUSHMODE = "RainBrushMode"             # 雨刷模式相关配置(对应 NET_A_CFG_RAINBRUSHMODE_INFO); Rain brush mode(NET_A_CFG_RAINBRUSHMODE_INFO)
    DIALRULE = "DialRule"                       # 拨号规则(CFG_DIALRULE_INFO);Dial rule (CFG_DIALRULE_INFO)
    BUILDING = "Building"                       # VTO楼层配置(CFG_BUILDING_INFO);VTO floor config (CFG_BUILDING_INFO)
    VTO_BASIC_INFO = "VTOBasicInfo"             # VTO基本信息 (对应 CFG_VTO_BASIC_INFO);VTO basic info (corresponding to CFG_VTO_BASIC_INFO)
    CFD_CMD_VTO_CALL_INFO_EXTEND = "VTOCallInfo"    # VTO呼叫配置扩展(对应结构体CFG_VTO_CALL_INFO_EXTEND);extend configuration of VTO call information(corresponding to CFG_VTO_CALL_INFO_EXTEND)
    VTH_NUMBER_INFO = "VTHNumberInfo"           # 室内机号码信息(对应 CFG_VTH_NUMBER_INFO);VTH no. info (corresponding to CFG_VTH_NUMBER_INFO)
    VTO_INFO = "VTOInfo"                        # 门口机配置(对应 CFG_VTO_LIST);VTO config (corresponding to CFG_VTO_LIST)
    VTO_CALL = "VTOCall"                        # VTO呼叫配置(CFG_VTO_CALL_INFO);VTO call config (CFG_VTO_CALL_INFO)
    VIDEO_IN_ZOOM = "VideoInZoom"               # 云台通道变倍配置(对应 CFG_VIDEO_IN_ZOOM);Zoom PTZ channel configuration(Corresponding CFG_VIDEO_IN_ZOOM)
    VIDEO_WIDGET2 = "VideoWidget2"              # 视频编码物件配置(对应结构体 CFG_VIDEO_WIDGET2_INFO);configuration of video encode staff(corresponding to CFG_VIDEO_WIDGET2_INFO)

class CFG_CAP_CMD_TYPE:
    """
    能力集命令  对应QueryNewSystemInfo/QueryNewSystemInfoEx接口; Capacity set command  Corresponding of QueryNewSystemInfo/QueryNewSystemInfoEx interface
    """
    PTZ = "ptz.getCurrentProtocolCaps"          # 获取云台能力集(CFG_PTZ_PROTOCOL_CAPS_INFO); Get PTZ capability set(CFG_PTZ_PROTOCOL_CAPS_INFO)

class NET_EM_CFG_OPERATE_TYPE(IntEnum):
    """
    配置操作类型,对应GetConfig和SetConfig接口;config type，corresponding to GetConfig and SetConfig interface
    """
    MEDIA_GLOBAL = 3,                           # 媒体组件全局配置, 对应结构体 NET_MEDIA_GLOBAL_INFO; media global config,corresponding to struct NET_MEDIA_GLOBAL_INFO
    DISABLE_BEEP_LINKAGE = 47,                  # 防蜂鸣联动项使能配置, 对应结构体 NET_CFG_DISABLE_BEEP_LINKAGE_INFO, 与通道不相关,通道号需要填成-1; Enable configuration of beep linkage item, corresponding to NET_CFG_DISABLE_BEEP_LINKAGE_INFO, not related to channels, ChannelID must be fill in -1
    AREA_ARM_MODE = 48,                         # Area布撤防配置, 对应结构体 NET_CFG_AREA_ARM_MODE_INFO, 与通道不相关,通道号需要填成-1; Area deployment and removal configuration, corresponding to NET_CFG_AREA_ARM_MODE_INFO, not related to channels, ChannelID must be fill in -1
    CFG_CHANNELTITLE = 1000,                    # 叠加通道标题属性配置，对应结构体 NET_OSD_CHANNEL_TITLE,其中结构体中的emOsdBlendType为必填参数; Encode widget-channel title config, corresponding to struct NET_OSD_CHANNEL_TITLE, emOsdBlendType in struct must be set
    CFG_TIMETITLE = 1001,                       # 叠加时间标题属性配置，对应结构体 NET_OSD_TIME_TITLE,其中结构体中的emOsdBlendType为必填参数; Encode widget-Time title config, corresponding to NET_OSD_TIME_TITLE, emOsdBlendType in struct must be set
    CFG_CUSTOMTITLE = 1002,                     # 叠加自定义标题属性配置，对应结构体 NET_OSD_CUSTOM_TITLE,其中结构体中的stuCustomTitle.emOsdBlendType为必填参数; Encode widget-Self-defined title config, corresponding to NET_OSD_CUSTOM_TITLE, emOsdBlendType  in struct must be set
    CFG_USER_DEF_TITLE = 1018,                  # 用户自定义OSD标题，对应结构体 NET_OSD_USER_DEF_TITLE
    CFG_GBMODE = 1021,                          # 视频OSD国标模式配置， 对应结构体NET_CFG_GBMODE_INFO;Video OSD national standard mode configuration, corresponding to structure NET_CFG_GBMODE_INFO
    ENCODE_VIDEO = 1100,                        # 编码视频格式属性配置，对应结构体 NET_ENCODE_VIDEO_INFO; Encode-video options config, corresponding to NET_ENCODE_VIDEO_INFO
    ENCODE_SNAP_INFO = 1106,                    # 编码抓图配置，对应结构体 NET_ENCODE_SNAP_INFO; Encode-video snap options config, corresponding to NET_ENCODE_SNAP_INFO
    ENCODE_SNAPTIME = 1107,                     # 编码抓图时间相关配置，对应结构体 NET_ENCODE_SNAP_TIME_INFO; Encode-video snap time options config, corresponding to NET_ENCODE_SNAP_TIME_INFO
    ENCODE_CHANNELTITLE = 1108,                 # 通道名称配置，对应结构体 NET_ENCODE_CHANNELTITLE_INFO;Encode-video channel title options config, corresponding to NET_ENCODE_CHANNELTITLE_INFO
    VIDEOIN_EXPOSURE_NORMAL = 1306,             # 曝光通用属性配置，对应结构体 NET_VIDEOIN_EXPOSURE_NORMAL_INFO;VideoIn-normal exposure config, corresponding to NET_VIDEOIN_EXPOSURE_NORMAL_INFO
    VIDEOIN_EXPOSURE_SHUTTER = 1308,            # 曝光快门配置，对应结构体 NET_VIDEOIN_EXPOSURE_SHUTTER_INFO ;Exposure shutter configuration, corresponding to the structure NET_VIDEOIN_EXPOSURE_SHUTTER_INFO
    NETAPP_COMMUNICATION_LIST = 1902,           # 通讯录配置, 对应结构体 NET_NETAPP_COMMUNICATION_LIST_CFG, 与通道不相关,通道号需要填成-1 ;
    SMART_MOTION_DETECT = 2109,                 # 智能动态检测配置, 对应结构体 NET_CFG_SMART_MOTION_DETECT; Smart motion detect configuration, corresponding to NET_CFG_SMART_MOTION_DETECT
    CFG_REGISTAR = 2301,                        # 注册服务器配置,对应结构体 NET_CFG_REGISTAR_INFO;VTH password configuration,corresponding to NET_CFG_VTH_PASSWORD_INFO
    CFG_SIP = 2302,                             # sip配置, 对应结构体 NET_CFG_SIPSERVER_INFO;registar server configuration,corresponding NET_CFG_REGISTAR_INFO
    SAFETYABNORMAL_ALARM = 3808,                # 安全异常报警配置, 对应结构体 NET_CFG_SAFETYABNORMAL_INFO; Security abnormal alarm configuration, corresponding to NET_CFG_SAFETYABNORMAL_INFO
    ACCESS_FUNCTION = 4011,                     # 接入功能配置, 对应结构体 NET_CFG_ACCESS_FUNCTION_INFO, 与通道不相关,通道号需要填成-1; Access function config corresponding to NET_CFG_ACCESS_FUNCTION_INFO, not related to channels, ChannelID must be fill in -1
    CFG_DISABLE_LINKAGE = 9300,                 # 一键撤防配置,对应结构体 NET_CFG_DISABLE_LINKAGE, 与通道不相关,通道号需要填成-1; Disable linkage configuration,corresponding to NET_CFG_DISABLE_LINKAGE,not related to channels,ChannelID must be fill in -1

class SDK_ALARM_TYPE(IntEnum):
    """
    报警事件类型, 在StartListenEx接口中使用; alarm event type, used in StartListenEx
    """
    ALARM_ALARM_EX = 0x2101,                    # 外部报警，数据字节数与设备报警通道个数相同，每个字节表示一个报警通道的报警状态，1为有报警，0为无报警; External alarm, the number of data bytes is the same as the number of alarm channels of the device, each byte represents the alarm state of an alarm channel, 1 means there is alarm, 0 means there is no alarm
    MOTION_ALARM_EX = 0x2102,                   # 动态检测报警，数据字节数与设备视频通道个数相同，每个字节表示一个视频通道的动态检测报警状态，1为有报警，0为无报警; The number of bytes of data is the same as the number of video channels of the device. Each byte represents the state of dynamic detection and alarm of a video channel. 1 indicates that there is alarm and 0 indicates that there is no alarm
    VIDEOLOST_ALARM_EX = 0x2103,                # 视频丢失报警，数据字节数与设备视频通道个数相同，每个字节表示一个视频通道的视频丢失报警状态，1为有报警，0为无报警; Video loss alarm
    SHELTER_ALARM_EX = 0x2104,                  # 视频遮挡报警，数据字节数与设备视频通道个数相同，每个字节表示一个视频通道的遮挡(黑屏)报警状态，1为有报警，0为无报警;
                                                # Video occlusion alarm, the number of data bytes is the same as the number of video channels of the device, each byte represents the occlusion (black screen) alarm state of a video channel, 1 means there is an alarm, 0 means no alarm
    DISKFULL_ALARM_EX = 0x2106,                 # 硬盘满报警，数据为1个字节，1为有硬盘满报警，0为无报警; Hard disk full alarm, data is 1 byte, 1 means hard disk full alarm, 0 means no alarm
    DISKERROR_ALARM_EX = 0x2107,                # 坏硬盘报警，数据为32个字节，每个字节表示一个硬盘的故障报警状态，1为有报警，0为无报警;
                                                # Bad hard disk alarm, the data is 32 bytes, each byte represents the fault alarm state of a hard disk, 1 is an alarm, 0 is no alaram
    ALARM_STORAGE_FAILURE = 0x2131,             # 存储异常报警(对应结构体 ALARM_STORAGE_FAILURE 数组); Store exception alarm (corresponding to the structure ALARM_STORAGE_FAILURE array)
    ALARM_FRONTDISCONNECT = 0x2132,             # 前端IPC断网报警(对应结构体 ALARM_FRONTDISCONNET_INFO); Front-end IPC disconnection alarm (corresponding to structure ALARM_FRONTDISCONNET_INFO)
    ALARM_ALARM_EX_REMOTE = 0x2133,             # 远程外部报警(对应结构体 ALARM_REMOTE_ALARM_INFO); Remote external alarm (corresponding to structure ALARM_REMOTE_ALARM_INFO)
    ALARM_BATTERYLOWPOWER = 0x2134,             # 电池电量低报警(对应结构体 NET_A_ALARM_BATTERYLOWPOWER_INFO); Low battery alarm (corresponding structure NET_A_ALARM_BATTERYLOWPOWER_INFO)
    ALARM_STORAGE_LOW_SPACE = 0x2145,           # 存储容量不足事件(对应 ALARM_STORAGE_LOW_SPACE_INFO); Insufficient storage capacity event (corresponding to ALARM_STORAGE_LOW_SPACE_INFO)
    ALARM_ALARM_EX2 = 0x2175,                   # 本地报警事件(对应结构体 NET_A_ALARM_ALARM_INFO_EX2,对 ALARM_ALARM_EX 升级); Local alarm event (corresponding structure NET_A_ALARM_ALARM_INFO_EX2, upgrade alarm_alarm_ex)
    EVENT_CROSSLINE_DETECTION = 0x2188,         # 警戒线事件( 对应结构体 NET_A_ALARM_EVENT_CROSSLINE_INFO ); Warning line events (corresponding structure NET_A_ALARM_EVENT_CROSSLINE_INFO)
    EVENT_CROSSREGION_DETECTION = 0x2189,       # 警戒区事件( 对应结构体 NET_A_ALARM_EVENT_CROSSREGION_INFO ); Alert zone events (corresponding structure NET_A_ALARM_EVENT_CROSSREGION_INFO)
    EVENT_FACE_DETECTION = 0x218b,              # 人脸检测事件( 对应结构体 ALARM_EVENT_FACE_INFO ); Human face detect event(Corresponding to structure ALARM_EVENT_FACE_INFO )
    ALARM_IPC = 0x218c,                         # IPC报警,IPC通过DVR或NVR上报的本地报警(对应结构体 NET_A_ALARM_IPC_INFO); IPC alarm: local alarm reported by IPC through DVR or NVR (corresponding to structure NET_A_ALARM_IPC_INFO)
    EVENT_MOTIONDETECT = 0x218f,                # 视频移动侦测事件(对应结构体 ALARM_MOTIONDETECT_INFO);Video motion detect event  (Corresponding to structure ALARM_MOTIONDETECT_INFO)
    ALARM_KEYPAD_TAMPER = 0x2199,               # 键盘防拆事件(对应结构体 NET_A_ALARM_KEYPAD_TAMPER_INFO); Keyboard disassembly prevention event (corresponding to the structure NET_A_ALARM_KEYPAD_TAMPER_INFO)
    ALARM_KEYPAD_FAILURE = 0x219A,              # 键盘掉线事件(对应结构体 NET_A_ALARM_KEYPAD_FAILURE_INFO); Keyboard disconnection event (corresponding to structure NET_A_ALARM_KEYPAD_FAILURE_INFO)
    ALARM_WIRELESS_DEVBATTERY_LOSS = 0x219C,    # 探测器电池丢失事件(对应结构体 NET_A_ALARM_WIRELESS_DEVBATTERY_LOSS_INFO); Detector battery loss event (corresponding structure NET_A_ALARM_WIRELESS_DEVBATTERY_LOSS_INFO)
    ALARM_SIREN_TAMPER = 0x219D,                # 警号防拆事件(对应结构体 NET_A_ALARM_SIREN_TAMPER_INFO); Alarm signal anti demolition event (corresponding structure NET_A_ALARM_SIREN_TAMPER_INFO)
    ALARM_KEYPAD_LOCK = 0x219E,                 # 键盘锁定事件(对应结构体 NET_A_ALARM_KEYPAD_LOCK_INFO); Keyboard lock event (corresponding to structure NET_A_ALARM_KEYPAD_LOCK_INFO)
    ALARM_NOGSMFIELD = 0x3014,                  # 通信模块掉线或者sim卡没插(对应结构体 NET_A_ALARM_NOGSMFIELD_INFO); The communication module is disconnected or the SIM card is not inserted (corresponding to the structure NET_A_ALARM_NOGSMFIELD_INFO)
    ALARM_POWERFAULT = 0x3172,                  # 电源故障事件(对应结构体 NET_A_ALARM_POWERFAULT_INFO); Power failure event (corresponding structure NET_A_ALARM_POWERFAULT_INFO)
    ALARM_CHASSISINTRUDED = 0x3173,             # 机箱入侵(防拆)报警事件(对应结构体 NET_A_ALARM_CHASSISINTRUDED_INFO); Chassis intrusion (disassembly prevention) alarm event (corresponding structure NET_A_ALARM_CHASSISINTRUDED_INFO)
    ALARM_ARMMODE_CHANGE_EVENT = 0x3175,        # 布撤防状态变化事件(对应结构体 NET_A_ALARM_ARMMODE_CHANGE_INFO); Deployment and removal status change event (corresponding structure NET_A_ALARM_ARMMODE_CHANGE_INFO)
    ALARM_ACCESS_CTL_EVENT = 0x3181,            # 门禁事件(对应结构体 NET_A_ALARM_ACCESS_CTL_EVENT_INFO); Access control event (corresponding to structure NET_A_ALARM_ACCESS_CTL_EVENT_INFO)
    ALARM_INPUT_SOURCE_SIGNAL = 0x3183,         # 报警输入源信号事件(只要有输入就会产生该事件, 不论防区当前的模式,无法屏蔽, 对应 NET_A_ALARM_INPUT_SOURCE_SIGNAL_INFO ); Alarm input source signal event (this event will be generated as long as there is an input. It cannot be masked regardless of the current mode of the zone, corresponding to NET_A_ALARM_INPUT_SOURCE_SIGNAL_INFO)
    ALARM_ACCESS_CTL_STATUS = 0x3185,           # 门禁状态事件(对应结构体 NET_A_ALARM_ACCESS_CTL_STATUS_INFO); Access control status event(corresponding structure NET_A_ALARM_ACCESS_CTL_STATUS_INFO)
    ALARM_RCEMERGENCY_CALL = 0x318b,            # 紧急呼叫报警事件(对应结构体 NET_A_ALARM_RCEMERGENCY_CALL_INFO); Emergency call alarm event (corresponding structure NET_A_ALARM_RCEMERGENCY_CALL_INFO)
    ALARM_LOGIN_FAILIUR = 0x3194,               # 登陆失败事件(对应结构体 NET_A_ALARM_LOGIN_FAILIUR_INFO); Login failed event (corresponding structure NET_A_ALARM_LOGIN_FAILIUR_INFO)
    ALARM_MODULE_LOST = 0x3195,                 # 扩展模块掉线事件(对应结构体 NET_A_ALARM_MODULE_LOST_INFO); Extension module disconnection event (corresponding structure NET_A_ALARM_MODULE_LOST_INFO)
    ALARM_PSTN_BREAK_LINE = 0x3196,             # PSTN掉线事件(对应结构体 NET_A_ALARM_PSTN_BREAK_LINE_INFO); PSTN drop event (corresponding structure NET_A_ALARM_PSTN_BREAK_LINE_INFO)
    ALARM_WIRELESSDEV_LOWPOWER = 0x31C8,        # 获取无线设备低电量上报事件(对应结构体 NET_A_ALARM_WIRELESSDEV_LOWPOWER_INFO); Get the wireless device low battery reporting event (corresponding structure NET_A_ALARM_WIRELESSDEV_LOWPOWER_INFO)
    ALARM_FIREWARNING_INFO = 0x31da,            # 热成像火情报警信息上报(对应结构体 NET_A_ALARM_FIREWARNING_INFO_DETAIL); Thermal imaging fire alarm information reporting (corresponding structure NET_A_ALARM_FIREWARNING_INFO_DETAIL)
    ALARM_SENSOR_ABNORMAL = 0x31dc,             # 探测器异常报警(对应结构体 NET_A_ALARM_SENSOR_ABNORMAL_INFO); Detector abnormal alarm (corresponding structure NET_A_ALARM_SENSOR_ABNORMAL_INFO)
    ALARM_RECORD_CHANGED_EX = 0x3211,           # 录像状态变化报警(对应结构体 ALARM_RECORD_CHANGED_INFO_EX); Recording state change alarm (corresponding to structure ALARM_RECORD_CHANGED_INFO_EX)
    ALARM_VIDEO_LOSS = 0x3242,                  # 视频丢失事件(对应 NET_A_ALARM_VIDEO_LOSS_INFO); Video loss event (corresponding to NET_A_ALARM_VIDEO_LOSS_INFO)
    ALARM_RECORD_SCHEDULE_CHANGE = 0x3307,      # 录像计划改变事件(对应结构体 ALARM_RECORD_SCHEDULE_CHANGE_INFO); Recording plan change event (corresponding to structure ALARM_RECORD_SCHEDULE_CHANGE_INFO)
    ALARM_HDD_TEMPERATUREALARM = 0x3309,        # 硬盘温度报警事件(对应结构体 ALARM_HDD_TEMPERATUREALARM_INFO); Hard disk temperature alarm event (corresponding structure ALARM_HDD_TEMPERATUREALARM_INFO)
    ALARM_HDD_HEALTHALARM = 0x330a,             # 硬盘健康状况报警事件(对应结构体 ALARM_HDD_HEALTHALARM_INFO); Hard disk health alarm event (corresponding structure ALARM_HDD_HEALTHALARM_INFO)
    ALARM_HDD_SHAKEALARM = 0x330b,              # 硬盘震动报警事件(对应结构体 ALARM_HDD_SHAKEALARM_INFO); Hard disk vibration alarm event (corresponding structure ALARM_HDD_SHAKEALARM_INFO)
    ALARM_AREAARM_MODECHANGE = 0x330e,          # 区域防区模式改变(对应结构体 NET_A_ALARM_AREAARM_MODECHANGE_INFO); Zone defense mode change (corresponding to structure NET_A_ALARM_AREAARM_MODECHANGE_INFO)
    ALARM_AREAALARM = 0x3310,                   # 区域报警(对应结构体 NET_A_ALARM_AREAALARM_INFO);Area alarm (corresponding structure NET_A_ALARM_AREAALARM_INFO)
    ALARM_TRAFFIC_XINKONG = 0x335f,             # 交通态势报警事件(对应结构体 NET_A_ALARM_TRAFFIC_XINKONG_INFO); Traffic situation alarm event (corresponding structure NET_A_ALARM_TRAFFIC_XINKONG_INFO)
    ALARM_RADAR_REGIONDETECTION = 0x3370,       # 雷达区域检测事件(对应结构体 NET_A_ALARM_RADAR_REGIONDETECTION_INFO); Radar area detection event (corresponding structure NET_A_ALARM_RADAR_REGIONDETECTION_INFO)
    ALARM_RADAR_LINEDETECTION = 0x3371,         # 雷达警戒线/绊线检测事件(对应结构体 NET_A_ALARM_RADAR_LINEDETECTION_INFO); Radar warning line / trip line detection event (corresponding to structure NET_A_ALARM_RADAR_LINEDETECTION_INFO)
    ALARM_DISK_CHECK = 0x3440,                  # 磁盘巡检报警事件(对应结构体 ALARM_DISK_CHECK_INFO); Disk patrol alarm event (corresponding structure ALARM_DISK_CHECK_INFO)
    ALARM_VEHICLE_INOUT = 0x346A,               # 车辆出入事件 (对应 NET_A_ALARM_VEHICLE_INOUT_INFO); Vehicle access event (corresponding to NET_A_ALARM_VEHICLE_INOUT_INFO)
    ALARM_WIRELESSDEV_POWERLESS = 0x3498,       # 探测器主电丢失事件 (对应结构体 NET_A_ALARM_WIRELESSDEV_POWERLESS_INFO); Detector main power loss event(corresponding structure NET_A_ALARM_WIRELESSDEV_POWERLESS_INFO)
    ALARM_TRAFFIC_FLOW_STAT = 0x349F,           # 交通路口车道统计事件(对应结构体 NET_A_ALARM_TRAFFIC_FLOW_STAT_INFO); Lane statistics events at traffic intersections (corresponding structure NET_A_ALARM_TRAFFIC_FLOW_STAT_INFO)
    ALARM_TRAFFIC_CAR_PASSING = 0x34A5,         # 车辆进出虚拟线圈状态事件(对应结构体 NET_A_ALARM_TRAFFIC_CAR_PASSING_INFO); Vehicle in and out virtual coil status event (corresponding structure NET_A_ALARM_TRAFFIC_CAR_PASSING_INFO)
    ALARM_SAFETY_ABNORMAL = 0x34AF,             # 安全报警事件(对应结构体 NET_ALARM_SAFETY_ABNORMAL_INFO); Security alarm event (corresponding structure NET_ALARM_SAFETY_ABNORMAL_INFO)
    ALARM_RF_JAMMING = 0x34C0,                  # RF干扰事件(对应结构体 NET_ALARM_RF_JAMMING_INFO); RF interference event (corresponding to structure NET_ALARM_RF_JAMMING_INFO)
    ALARM_ARMING_FAILURE = 0x34C1,              # 布防失败事件(对应结构体 NET_ALARM_ARMING_FAILURE_INFO); Deployment failure event (corresponding structure NET_ALARM_ARMING_FAILURE_INFO)
    ALARM_USER_MODIFIED = 0x34C2,               # 用户信息被修改(增加、删除、修改)事件(对应结构体 NET_ALARM_USER_MODIFIED_INFO); User information is modified (added, deleted, modified) event (corresponding structure NET_ALARM_USER_MODIFIED_INFO)
    ALARM_MANUAL_TEST = 0x34C3,                 # 手动测试事件(对应结构体 NET_ALARM_MANUAL_TEST_INFO); Manual test event (corresponding structure NET_ALARM_MANUAL_TEST_INFO)
    ALARM_DEVICE_MODIFIED = 0x34C4,             # 设备设息修改(增加、删除、修改)事件(对应结构体 NET_ALARM_DEVICE_MODIFIED_INFO); Equipment setting modification (add, delete, modify) event (corresponding structure NET_ALARM_DEVICE_MODIFIED_INFO)
    ALARM_ATS_FAULT = 0x34C5,                   # 报警传输系统故障事件(对应结构体 NET_ALARM_ATS_FAULT_INFO); Alarm transmission system fault event (corresponding structure NET_ALARM_ATS_FAULT_INFO)
    ALARM_ARC_OFFLINE = 0x34C6,                 # 报警接收中心离线事件(对应结构体 NET_ALARM_ARC_OFFLINE_INFO); Offline event of alarm receiving center (corresponding structure NET_ALARM_ARC_OFFLINE_INFO)
    ALARM_WIFI_FAILURE = 0x34C7,                # wifi故障事件(对应结构体 NET_ALARM_WIFI_FAILURE_INFO); WiFi failure event (corresponding structure NET_ALARM_WIFI_FAILURE_INFO)
    ALARM_OVER_TEMPERATURE = 0x34C8,            # 超温报警事件(对应结构体 NET_ALARM_OVER_TEMPERATURE_INFO); Overtemperature alarm event (corresponding structure NET_ALARM_OVER_TEMPERATURE_INFO)

class CtrlType(IntEnum):
    """
    """
    REBOOT = 0,                                 # 重启设备; Reboot device;
    SHUTDOWN = 1,                               # 关闭设备; Shut down device;
    DISK = 2,                                   # 硬盘管理; HDD management;
    KEYBOARD_POWER = 3,                         # 网络键盘; Network keyboard;
    KEYBOARD_ENTER = 4,
    KEYBOARD_ESC = 5,
    KEYBOARD_UP = 6,
    KEYBOARD_DOWN = 7,
    KEYBOARD_LEFT = 8,
    KEYBOARD_RIGHT = 9,
    KEYBOARD_BTN0 = 10,
    KEYBOARD_BTN1 = 11,
    KEYBOARD_BTN2 = 12,
    KEYBOARD_BTN3 = 13,
    KEYBOARD_BTN4 = 14,
    KEYBOARD_BTN5 = 15,
    KEYBOARD_BTN6 = 16,
    KEYBOARD_BTN7 = 17,
    KEYBOARD_BTN8 = 18,
    KEYBOARD_BTN9 = 19,
    KEYBOARD_BTN10 = 20,
    KEYBOARD_BTN11 = 21,
    KEYBOARD_BTN12 = 22,
    KEYBOARD_BTN13 = 23,
    KEYBOARD_BTN14 = 24,
    KEYBOARD_BTN15 = 25,
    KEYBOARD_BTN16 = 26,
    KEYBOARD_SPLIT = 27,
    KEYBOARD_ONE = 28,
    KEYBOARD_NINE = 29,
    KEYBOARD_ADDR = 30,
    KEYBOARD_INFO = 31,
    KEYBOARD_REC = 32,
    KEYBOARD_FN1 = 33,
    KEYBOARD_FN2 = 34,
    KEYBOARD_PLAY = 35,
    KEYBOARD_STOP = 36,
    KEYBOARD_SLOW = 37,
    KEYBOARD_FAST = 38,
    KEYBOARD_PREW = 39,
    KEYBOARD_NEXT = 40,
    KEYBOARD_JMPDOWN = 41,
    KEYBOARD_JMPUP = 42,
    KEYBOARD_10PLUS = 43,
    KEYBOARD_SHIFT = 44,
    KEYBOARD_BACK = 45,
    KEYBOARD_LOGIN = 46,                        # 新网络键盘功能; new network keyboard function;
    KEYBOARD_CHNNEL = 47,                       # 切换视频通道; switch video channel;
    TRIGGER_ALARM_IN = 100,                     # 触发报警输入; Activate alarm input;
    TRIGGER_ALARM_OUT = 101,                    # 触发报警输出; Activate alarm output;
    MATRIX = 102,                               # 矩阵控制; Matrix control;
    SDCARD = 103,                               # SD卡控制(IPC产品)参数同硬盘控制; SD card control(for IPC series). Please refer to HDD control;
    BURNING_START = 104,                        # 刻录机控制,开始刻录; Burner control:begin burning;
    BURNING_STOP = 105,                         # 刻录机控制,结束刻录; Burner control:stop burning;
    BURNING_ADDPWD = 106,                       # 刻录机控制,叠加密码(以'\0'为结尾的字符串,最大长度8位); Burner control:overlay password(The string ended with '\0'. Max length is 8 bits. );
    BURNING_ADDHEAD = 107,                      # 刻录机控制,叠加片头(以'\0'为结尾的字符串,最大长度1024字节,支持分行,行分隔符'\n'); Burner control:overlay head title(The string ended with '\0'. Max length is 1024 bytes. Use '\n' to Enter.);
    BURNING_ADDSIGN = 108,                      # 刻录机控制,叠加打点到刻录信息(参数无); Burner control:overlay dot to the burned information(No parameter);
    BURNING_ADDCURSTOMINFO = 109,               # 刻录机控制,自定义叠加(以'\0'为结尾的字符串,最大长度1024字节,支持分行,行分隔符'\n'); Burner control:self-defined overlay (The string ended with '\0'. Max length is 1024 bytes. Use '\n' to Enter);
    RESTOREDEFAULT = 110,                       # 恢复设备的默认设置 对应枚举操作码 EM_RESTORE_TYPE; restore device default setup;
    CAPTURE_START = 111,                        # 触发设备抓图; Activate device snapshot;
    CLEARLOG = 112,                             # 清除日志; Clear log;
    TRIGGER_ALARM_WIRELESS = 200,               # 触发无线报警(IPC产品); Activate wireless alarm (IPC series);
    MARK_IMPORTANT_RECORD = 201,                # 标识重要录像文件; Mark important record;
    DISK_SUBAREA = 202,                         # 网络硬盘分区; Network hard disk partition;
    BURNING_ATTACH = 203,                       # 刻录机控制,附件刻录.; Annex burning;
    BURNING_PAUSE = 204,                        # 刻录暂停; Burn Pause;
    BURNING_CONTINUE = 205,                     # 刻录继续; Burn Resume;
    BURNING_POSTPONE = 206,                     # 刻录顺延; Burn Postponed;
    OEMCTRL = 207,                              # 报停控制; OEM control;
    BACKUP_START = 208,                         # 设备备份开始; Start to device backup;
    BACKUP_STOP = 209,                          # 设备备份停止; Stop to device backup;
    VIHICLE_WIFI_ADD = 210,                     # 车载手动增加WIFI配置; Add WIFI configuration manually for car device;
    VIHICLE_WIFI_DEC = 211,                     # 车载手动删除WIFI配置; Delete WIFI configuration manually for car device;
    BUZZER_START = 212,                         # 蜂鸣器控制开始; Start to buzzer control;
    BUZZER_STOP = 213,                          # 蜂鸣器控制结束; Stop to buzzer control;
    REJECT_USER = 214,                          # 剔除用户; Reject User;
    SHIELD_USER = 215,                          # 屏蔽用户; Shield User;
    RAINBRUSH = 216,                            # 智能交通, 雨刷控制; Rain Brush;
    MANUAL_SNAP = 217,                          # 智能交通, 手动抓拍 (对应结构体 MANUAL_SNAP_PARAMETER); manual snap (struct MANUAL_SNAP_PARAMETER);
    MANUAL_NTP_TIMEADJUST = 218,                # 手动NTP校时; manual ntp time adjust;
    NAVIGATION_SMS = 219,                       # 导航信息和短消息; navigation info and note;
    ROUTE_CROSSING = 220,                       # 路线点位信息; route info;
    BACKUP_FORMAT = 221,                        # 格式化备份设备; backup device format;
    DEVICE_LOCALPREVIEW_SLIPT = 222,            # 控制设备端本地预览分割(对应结构体DEVICE_LOCALPREVIEW_SLIPT_PARAMETER); local preview split(struct DEVICE_LOCALPREVIEW_SLIPT_PARAMETER);
    INIT_RAID = 223,                            # RAID初始化; RAID init;
    RAID = 224,                                 # RAID操作; RAID control;
    SAPREDISK = 225,                            # 热备盘操作; sapredisk control;
    WIFI_CONNECT = 226,                         # 手动发起WIFI连接(对应结构体WIFI_CONNECT); wifi connect(struct WIFI_CONNECT);
    WIFI_DISCONNECT = 227,                      # 手动断开WIFI连接(对应结构体WIFI_CONNECT); wifi disconnect(struct WIFI_CONNECT);
    ARMED = 228,                                # 布撤防操作; Arm/disarm operation;
    IP_MODIFY = 229,                            # 修改前端IP(对应结构体DHCTRL_IPMODIFY_PARAM); IP modify(struct DHCTRL_IPMODIFY_PARAM);
    WIFI_BY_WPS = 230,                          # wps连接wifi(对应结构体DHCTRL_CONNECT_WIFI_BYWPS); wps connect wifi(struct DHCTRL_CONNECT_WIFI_BYWPS);
    FORMAT_PATITION = 231,                      # 格式化分区(对应结构体 NET_A_FORMAT_PATITION); format pattion (struct NET_A_FORMAT_PATITION);
    EJECT_STORAGE = 232,                        # 手动卸载设备(对应结构体EJECT_STORAGE_DEVICE); eject storage device(struct EJECT_STORAGE_DEVICE);
    LOAD_STORAGE = 233,                         # 手动装载设备(对应结构体LOAD_STORAGE_DEVICE); load storage device(struct LOAD_STORAGE_DEVICE);
    CLOSE_BURNER = 234,                         # 关闭刻录机光驱门(对应结构体 NET_CTRL_BURNERDOOR) 一般需要等6秒; close burner(struct NET_CTRL_BURNERDOOR) need wait 6s;
    EJECT_BURNER = 235,                         # 弹出刻录机光驱门(对应结构体 NET_CTRL_BURNERDOOR) 一般需要等4秒; eject burner(struct NET_CTRL_BURNERDOOR) need wait 4s;
    CLEAR_ALARM = 236,                          # 消警(对应结构体 NET_CTRL_CLEAR_ALARM); alarm elimination (corresponding structure NET_CTRL_CLEAR_ALARM);
    MONITORWALL_TVINFO = 237,                   # 电视墙信息显示(对应结构体 NET_CTRL_MONITORWALL_TVINFO); TV wall information display (corresponding structure NET_CTRL_MONITORWALL_TVINFO);
    START_VIDEO_ANALYSE = 238,                  # 开始视频智能分析(对应结构体 NET_CTRL_START_VIDEO_ANALYSE); start Intelligent VIDEO analysis (corresponding structure NET_CTRL_START_VIDEO_ANALYSE);
    STOP_VIDEO_ANALYSE = 239,                   # 停止视频智能分析(对应结构体 NET_CTRL_STOP_VIDEO_ANALYSE); STOP intelligent VIDEO analysis (corresponding structure NET_CTRL_STOP_VIDEO_ANALYSE);
    UPGRADE_DEVICE = 240,                       # 控制启动设备升级,由设备独立完成升级过程,不需要传输升级文件; Controlled start equipment upgrades, independently complete the upgrade process by the equipment do not need to upgrade file;
    MULTIPLAYBACK_CHANNALES = 241,              # 切换多通道预览回放的通道(对应结构体 NET_CTRL_MULTIPLAYBACK_CHANNALES); Multi-channel preview playback channel switching (corresponding structure NET_CTRL MULTIPLAYBACK CHANNALES);
    SEQPOWER_OPEN = 242,                        # 电源时序器打开开关量输出口(对应 NET_CTRL_SEQPOWER_PARAM); Turn on the switch power supply timing device output (corresponding NET_CTRL SEQPOWER PARAM);
    SEQPOWER_CLOSE = 243,                       # 电源时序器关闭开关量输出口(对应 NET_CTRL_SEQPOWER_PARAM); Close the switch power supply timing device output (corresponding NET_CTRL SEQPOWER PARAM);
    SEQPOWER_OPEN_ALL = 244,                    # 电源时序器打开开关量输出口组(对应 NET_CTRL_SEQPOWER_PARAM); Power timing group open the switch quantity output (corresponding NET_CTRL SEQPOWER PARAM);
    SEQPOWER_CLOSE_ALL = 245,                   # 电源时序器关闭开关量输出口组(对应 NET_CTRL_SEQPOWER_PARAM); Power sequence set close the switch quantity output (corresponding NET_CTRL SEQPOWER PARAM);
    PROJECTOR_RISE = 246,                       # 投影仪上升(对应 NET_CTRL_PROJECTOR_PARAM); PROJECTOR up (corresponding NET_CTRL_PROJECTOR PARAM);
    PROJECTOR_FALL = 247,                       # 投影仪下降(对应 NET_CTRL_PROJECTOR_PARAM); PROJECTOR drop (corresponding to NET_CTRL_PROJECTOR PARAM);
    PROJECTOR_STOP = 248,                       # 投影仪停止(对应 NET_CTRL_PROJECTOR_PARAM); PROJECTOR stop (corresponding to the NET_CTRL_PROJECTOR PARAM);
    INFRARED_KEY = 249,                         # 红外按键(对应 NET_CTRL_INFRARED_KEY_PARAM); INFRARED buttons (corresponding to the NET_CTRL_INFRARED KEY PARAM);
    START_PLAYAUDIO = 250,                      # 设备开始播放音频文件(对应结构体 NET_CTRL_START_PLAYAUDIO); Device START playback of audio file corresponding structure NET_CTRL START PLAYAUDIO);
    STOP_PLAYAUDIO = 251,                       # 设备停止播放音频文件; Equipment stop playback of audio file;
    START_ALARMBELL = 252,                      # 开启警号(对应结构体 NET_CTRL_ALARMBELL); open alarm (Corresponding to NET_CTRL_ALARMBELL);
    STOP_ALARMBELL = 253,                       # 关闭警号(对应结构体 NET_CTRL_ALARMBELL); Close the warning signal (corresponding structure NET_CTRL ALARMBELL);
    ACCESS_OPEN = 254,                          # 门禁控制-开门(对应结构体 NET_CTRL_ACCESS_OPEN); OPEN ACCESS control (corresponding structure NET_CTRL_ACCESS_OPEN);
    SET_BYPASS = 255,                           # 设置旁路功能(对应结构体 NET_CTRL_SET_BYPASS); By pass (Corresponding to NET_CTRL_SET_BYPASS);
    RECORDSET_INSERT = 256,                     # 添加记录,获得记录集编号(对应 NET_CTRL_RECORDSET_INSERT_PARAM); Add records to record set number (corresponding to the NET_CTRL_RECORDSET_INSERT_PARAM);
    RECORDSET_UPDATE = 257,                     # 更新某记录集编号的记录(对应 NET_CTRL_RECORDSET_PARAM); Update a record of the number (corresponding to the NET_CTRL_RECORDSET_PARAM);
    RECORDSET_REMOVE = 258,                     # 根据记录集编号删除某记录(对应 NET_CTRL_RECORDSET_PARAM); According to the record set number to delete a record (corresponding to the NET_CTRL_RECORDSET_PARAM);
    RECORDSET_CLEAR = 259,                      # 清除所有记录集信息(对应 NET_CTRL_RECORDSET_PARAM); Remove all RECORDSET information (corresponding to the NET_CTRL_RECORDSET_PARAM);
    ACCESS_CLOSE = 260,                         # 门禁控制-关门(对应结构体 NET_CTRL_ACCESS_CLOSE); Entrance guard control - CLOSE corresponding structure NET_CTRL_ACCESS_CLOSE);
    ALARM_SUBSYSTEM_ACTIVE_SET = 261,           # 报警子系统激活设置(对应结构体NET_CTRL_ALARM_SUBSYSTEM_SETACTIVE); Alarm sub system activation setup(corresponding structure NET_CTRL_ALARM_SUBSYSTEM_SETACTIVE);
    FORBID_OPEN_STROBE = 262,                   # 禁止设备端开闸(对应结构体 NET_CTRL_FORBID_OPEN_STROBE); unable device open gateway(corresponding to structure NET_CTRL_FORBID_OPEN_STROBE);
    OPEN_STROBE = 263,                          # 开启道闸(对应结构体 NET_CTRL_OPEN_STROBE); Enable gateway(corresponding to structure NET_CTRL_OPEN_STROBE);
    TALKING_REFUSE = 264,                       # 对讲拒绝接听(对应结构体 NET_CTRL_TALKING_REFUSE); Talk no response(corresponding to structure NET_CTRL_TALKING_REFUSE);
    ARMED_EX = 265,                             # 布撤防操作(对应结构体 CTRL_ARM_DISARM_PARAM_EX), 对CTRL_ARM_DISARM_PARAM 升级,建议用这个; arm-disarm operation(corresponding to structure CTRL_ARM_DISARM_PARAM_EX), CTRL_ARM_DISARM_PARAM upgrade, recommended;
    REMOTE_TALK = 266,                          # 远程对讲控制(对应结构体NET_CTRL_REMOTETALK_PARAM); Remote talk control(corresponding to structure NET_CTRL_REMOTETALK_PARAM);
    NET_KEYBOARD = 400,                         # 网络键盘控制(对应结构体 DHCTRL_NET_KEYBOARD); Net keyboard control(corresponding to structure DHCTRL_NET_KEYBOARD);
    AIRCONDITION_OPEN = 401,                    # 打开空调(对应结构体 NET_CTRL_OPEN_AIRCONDITION); Open air conditioner(corresponding to structure NET_CTRL_OPEN_AIRCONDITION);
    AIRCONDITION_CLOSE = 402,                   # 关闭空调(对应结构体 NET_CTRL_CLOSE_AIRCONDITION); Close air-conditioner(corresponding to structure NET_CTRL_CLOSE_AIRCONDITION);
    AIRCONDITION_SET_TEMPERATURE = 403,         # 设定空调温度(对应结构体 NET_CTRL_SET_TEMPERATURE); Set temperature (corresponding to structure NET_CTRL_SET_TEMPERATURE);
    AIRCONDITION_ADJUST_TEMPERATURE = 404,      # 调节空调温度(对应结构体 NET_CTRL_ADJUST_TEMPERATURE); Adjust temperature(corresponding to structure NET_CTRL_ADJUST_TEMPERATURE);
    AIRCONDITION_SETMODE = 405,                 # 设置空调工作模式(对应结构体 NET_CTRL_ADJUST_TEMPERATURE); Set air work mode(corresponding to structure NET_CTRL_ADJUST_TEMPERATURE);
    AIRCONDITION_SETWINDMODE = 406,             # 设置空调送风模式(对应结构体 NET_CTRL_AIRCONDITION_SETMODE); Set fan mode(corresponding to structure NET_CTRL_AIRCONDITION_SETMODE);
    RESTOREDEFAULT_EX = 407,                    # 恢复设备的默认设置新协议(对应结构体NET_CTRL_RESTORE_DEFAULT),恢复配置优先使用该枚举,如果接口失败,,且CLIENT_GetLastError返回NET_UNSUPPORTED,再尝试使用RESTOREDEFAULT恢复配置; Recover device default and set new protocol(corresponding to structure NET_CTRL_RESTORE_DEFAULT),Recover config and use this enumeration first, if port failed,,and CLIENT_GetLastError return NET_UNSUPPORTED, try again RESTOREDEFAULT restore config;
    NOTIFY_EVENT = 408,                         # 向设备发送事件(对应结构体 NET_NOTIFY_EVENT_DATA); send event to device (corresponding to structure NET_NOTIFY_EVENT_DATA);
    SILENT_ALARM_SET = 409,                     # 无声报警设置; mute alarm setup;
    START_PLAYAUDIOEX = 410,                    # 设备开始语音播报(对应结构体 NET_CTRL_START_PLAYAUDIOEX); device start sound report(corresponding to structure NET_CTRL_START_PLAYAUDIOEX);
    STOP_PLAYAUDIOEX = 411,                     # 设备停止语音播报; device stop sound report;
    CLOSE_STROBE = 412,                         # 关闭道闸(对应结构体 NET_CTRL_CLOSE_STROBE); close gateway(corresponding to structure NET_CTRL_CLOSE_STROBE);
    SET_ORDER_STATE = 413,                      # 设置车位预定状态(对应结构体 NET_CTRL_SET_ORDER_STATE); set parking reservation status (corresponding to structure NET_CTRL_SET_ORDER_STATE);
    RECORDSET_INSERTEX = 414,                   # 添加记录,获得记录集编号(对应 NET_CTRL_RECORDSET_INSERT_PARAM); add record get record collection no.(corresponding to NET_CTRL_RECORDSET_INSERT_PARAM);
    RECORDSET_UPDATEEX = 415,                   # 更新记录集编号的记录(对应NET_CTRL_RECORDSET_PARAM); update finger print record set no record(corresponding to NET_CTRL_RECORDSET_PARAM);
    CAPTURE_FINGER_PRINT = 416,                 # 采集(对应结构体 NET_CTRL_CAPTURE_FINGER_PRINT); collection (corresponding to structure NET_CTRL_CAPTURE_FINGER_PRINT);
    ECK_LED_SET = 417,                          # 停车场出入口控制器LED设置(对应结构体 NET_CTRL_ECK_LED_SET_PARAM); Parking lot entrance/exit controller LED setup(corresponding structure NET_CTRL_ECK_LED_SET_PARAM);
    ECK_IC_CARD_IMPORT = 418,                   # 智能停车系统出入口机IC卡信息导入(对应结构体 NET_CTRL_ECK_IC_CARD_IMPORT_PARAM); Intelligent parking system in/out device IC card info import (corresponding structure NET_CTRL_ECK_IC_CARD_IMPORT_PARAM);
    ECK_SYNC_IC_CARD = 419,                     # 智能停车系统出入口机IC卡信息同步指令,收到此指令后,设备删除原有IC卡信息(对应结构体 NET_CTRL_ECK_SYNC_IC_CARD_PARAM); Intelligent parking system in/out device IC card info sync command, receive this command, device will delete original IC card info(corresponding structure NET_CTRL_ECK_SYNC_IC_CARD_PARAM);
    LOWRATEWPAN_REMOVE = 420,                   # 删除指定无线设备(对应结构体 NET_CTRL_LOWRATEWPAN_REMOVE); Delete specific wireless device(corresponding structure NET_CTRL_LOWRATEWPAN_REMOVE);
    LOWRATEWPAN_MODIFY = 421,                   # 修改无线设备信息(对应结构体 NET_CTRL_LOWRATEWPAN_MODIFY); Modify wireless device info(corresponding structure NET_CTRL_LOWRATEWPAN_MODIFY);
    ECK_SET_PARK_INFO = 422,                    # 智能停车系统出入口机设置车位信息(对应结构体 NET_CTRL_ECK_SET_PARK_INFO_PARAM); Set up the vehicle spot information of the machine at the passageway of the intelligent parking system (corresponding to NET_CTRL_ECK_SET_PARK_INFO_PARAM);
    VTP_DISCONNECT = 423,                       # 挂断视频电话(对应结构体 NET_CTRL_VTP_DISCONNECT); hang up the video phone (corresponding to NET_CTRL_VTP_DISCONNECT);
    UPDATE_FILES = 424,                         # 远程投放多媒体文件更新(对应结构体 NET_CTRL_UPDATE_FILES); the update of the remote multimedia files (corresponding to NET_CTRL_UPDATE_FILES);
    MATRIX_SAVE_SWITCH = 425,                   # 保存上下位矩阵输出关系(对应结构体 NET_CTRL_MATRIX_SAVE_SWITCH); Save up the relationship between the hyponymy matrixes (corresponding to NET_CTRL_MATRIX_SAVE_SWITCH);
    MATRIX_RESTORE_SWITCH = 426,                # 恢复上下位矩阵输出关系(对应结构体 NET_CTRL_MATRIX_RESTORE_SWITCH); recover the relationship between the hyponymy matrixes (corresponding to NET_CTRL_MATRIX_RESTORE_SWITCH);
    VTP_DIVERTACK = 427,                        # 呼叫转发响应(对应结构体 NET_CTRL_VTP_DIVERTACK); video talk phone divert ack(corresponding to NET_CTRL_VTP_DIVERTACK);
    RAINBRUSH_MOVEONCE = 428,                   # 雨刷来回刷一次,雨刷模式配置为手动模式时有效(对应结构体 NET_CTRL_RAINBRUSH_MOVEONCE); Rain-brush brush one time, efficient when set as manual mode(corresponding to NET_CTRL_RAINBRUSH_MOVEONCE);
    RAINBRUSH_MOVECONTINUOUSLY = 429,           # 雨刷来回循环刷,雨刷模式配置为手动模式时有效(对应结构体 NET_CTRL_RAINBRUSH_MOVECONTINUOUSLY); Rain-brush brush cyclic, efficient when set as manal mode(corresponding to NET_CTRL_RAINBRUSH_MOVECONTINUOUSLY);
    RAINBRUSH_STOPMOVE = 430,                   # 雨刷停止刷,雨刷模式配置为手动模式时有效(对应结构体 NET_CTRL_RAINBRUSH_STOPMOVE); Rain-brush stop, efficient when set as manal mode(corresponding to NET_CTRL_RAINBRUSH_STOPMOVE);
    ALARM_ACK = 431,                            # 报警事件确认(对应结构体 NET_CTRL_ALARM_ACK),ALARM_ACK 该操作切勿在报警回调接口中调用; affirm the alarm event(corresponding to NET_CTRL_ALARM_ACK)  ALARM_ACK DO NOT call this method in callback interface;
    RECORDSET_IMPORT = 432,                     # 批量导入记录集信息(对应NET_CTRL_RECORDSET_PARAM); Batch import record set info (Corresponding to NET_CTRL_RECORDSET_PARAM);
    DELIVERY_FILE = 433,                        # 向视频输出口投放视频和图片文件, 楼宇对讲使用，同一时间投放(对应NET_CTRL_DELIVERY_FILE); Delivery file to the video output port, building intercom use, run at the same time(Corresponding to NET_CTRL_DELIVERY_FILE);
    FORCE_BREAKING = 434,                       # 强制产生违章类型(对应 NET_CTRL_FORCE_BREAKING); Force breaking rule(Corresponding to NET_CTRL_FORCE_BREAKING);
    RESTORE_EXCEPT = 435,                       # 恢复除指定配置外的其他配置为默认。; Restore the configuration except the prescribed config.;
    SET_PARK_INFO = 436,                        # 设置停车信息，平台设置给相机，内容用于点阵屏显示(对应结构体 NET_CTRL_SET_PARK_INFO); Set park info, platform is set to camera,the content is used for the dot matrix display(corresponding to NET_CTRL_SET_PARK_INFO);
    CLEAR_SECTION_STAT = 437,                   # 清除当前时间段内人数统计信息, 重新从0开始计算(对应结构体NET_CTRL_CLEAR_SECTION_STAT_INFO); clear the statistics for the period and start again from 0 (Corresponding to NET_CTRL_CLEAR_SECTION_STAT_INFO);
    DELIVERY_FILE_BYCAR = 438,                  # 向视频输出口投放视频和图片文件, 车载使用，广告单独时间投放(对应NET_CTRL_DELIVERY_FILE_BYCAR); Send video and image files to video output, Used by car, The ad time is served separately(Corresponding NET_CTRL_DELIVERY_FILE_BYCAR);
    ECK_GUIDINGPANEL_CONTENT = 439,             # 设置诱导屏显示内容(对应结构体 NET_CTRL_ECK_GUIDINGPANEL_CONTENT); set guiding panel content( NET_CTRL_ECK_GUIDINGPANEL_CONTENT );
    SET_SAFE_LEVEL = 440,                       # 设置门禁安全等级(对应结构体，pInBuf= NET_IN_SET_SAFE_LEVEL*, pOutBuf= NET_OUT_SET_SAFE_LEVEL * ); set safe level(pInBuf= NET_IN_SET_SAFE_LEVEL*, pOutBuf= NET_OUT_SET_SAFE_LEVEL * );
    VTP_INVITEACK = 441,                        # 对讲请求回复(对应结构体 NET_CTRL_VTP_INVITEACK); video talk peer invite ack(corresponding to NET_CTRL_VTP_INVITEACK);
    ACCESS_RESET_PASSWORD = 442,                # 门禁控制-重置密码(对应结构体 NET_CTRL_ACCESS_RESET_PASSWORD); access control - reset password (corresponding to structure NET_CTRL_ACCESS_RESET_PASSWORD);
    ACCESS_CALL_LIFT = 443,                     # 门禁控制-呼梯(对应结构体 NET_CTRL_ACCESS_CALL_LIFT); access control - call lift(corresponding to structure NET_CTRL_ACCESS_CALL_LIFT);
                                                # 以下命令只在CLIENT_ControlDeviceEx上有效
    THERMO_GRAPHY_ENSHUTTER = 0x10000,          # 设置热成像快门启用 / 禁用, pInBuf = NET_IN_THERMO_EN_SHUTTER *, pOutBuf = NET_OUT_THERMO_EN_SHUTTER *
    RADIOMETRY_SETOSDMARK = 0x10001,            # 设置测温项的osd为高亮, pInBuf = NET_IN_RADIOMETRY_SETOSDMARK *, pOutBuf = NET_OUT_RADIOMETRY_SETOSDMARK *
    AUDIO_REC_START_NAME = 0x10002,             # 开启音频录音并得到录音名, pInBuf = NET_IN_AUDIO_REC_MNG_NAME *, pOutBuf = NET_OUT_AUDIO_REC_MNG_NAME *
    AUDIO_REC_STOP_NAME = 0x10003,              # 关闭音频录音并返回文件名称, pInBuf = NET_IN_AUDIO_REC_MNG_NAME *, pOutBuf = NET_OUT_AUDIO_REC_MNG_NAME *
    SNAP_MNG_SNAP_SHOT = 0x10004,               # 即时抓图(又名手动抓图), pInBuf = NET_IN_SNAP_MNG_SHOT *, pOutBuf = NET_OUT_SNAP_MNG_SHOT *
    LOG_STOP = 0x10005,                         # 强制同步缓存数据到数据库并关闭数据库, pInBuf = NET_IN_LOG_MNG_CTRL *, pOutBuf = NET_OUT_LOG_MNG_CTRL *
    LOG_RESUME = 0x10006,                       # 恢复数据库, pInBuf = NET_IN_LOG_MNG_CTRL *, pOutBuf = NET_OUT_LOG_MNG_CTRL *
    POS_ADD = 0x10007,                          # 增加一个Pos设备, pInBuf = NET_IN_POS_ADD *, pOutBuf = NET_OUT_POS_ADD *
    POS_REMOVE = 0x10008,                       # 删除一个Pos设备, pInBuf = NET_IN_POS_REMOVE *, pOutBuf = NET_OUT_POS_REMOVE *
    POS_REMOVE_MULTI = 0x10009,                 # 批量删除Pos设备, pInBuf = NET_IN_POS_REMOVE_MULTI *, pOutBuf = NET_OUT_POS_REMOVE_MULTI *
    POS_MODIFY = 0x1000a,                       # 修改一个Pos设备, pInBuf = NET_IN_POS_ADD *, pOutBuf = NET_OUT_POS_ADD *
    SET_SOUND_ALARM = 0x1000b,                  # 触发有声报警, pInBuf = NET_IN_SOUND_ALARM *, pOutBuf = NET_OUT_SOUND_ALARM *
    AUDIO_MATRIX_SILENCE = 0x1000c,             # 音频举证一键静音控制(对应pInBuf=NET_IN_AUDIO_MATRIX_SILENCE, pOutBuf=NET_OUT_AUDIO_MATRIX_SILENCE)
    MANUAL_UPLOAD_PICTURE = 0x1000d,            # 设置手动上传, pInBuf = NET_IN_MANUAL_UPLOAD_PICTURE *, pOutBUf = NET_OUT_MANUAL_UPLOAD_PICTURE *
    REBOOT_NET_DECODING_DEV = 0x1000e,          # 重启网络解码设备, pInBuf = NET_IN_REBOOT_NET_DECODING_DEV *, pOutBuf = NET_OUT_REBOOT_NET_DECODING_DEV *
    SET_IC_SENDER = 0x1000f,                    # ParkingControl设置发卡设备, pInBuf = NET_IN_SET_IC_SENDER *, pOutBuf = NET_OUT_SET_IC_SENDER *
    SET_MEDIAKIND = 0x10010,                    # 设置预览码流组成, 如仅音频, 仅视频, 音视频pInBuf = NET_IN_SET_MEDIAKIND *, pOutBuf = NET_OUT_SET_MEDIAKIND *
                                                # 配合功能列表能力集使用, EN_ENCODE_CHN, 2 - 预览支持音视频分开获取
    LOWRATEWPAN_ADD = 0x10011,                  # 增加无线设备信息(对应结构体pInBuf = NET_CTRL_LOWRATEWPAN_ADD *, pOutBUf = NULL)
    LOWRATEWPAN_REMOVEALL = 0x10012,            # 删除所有的无线设备信息(对应结构体pInBuf = NET_CTRL_LOWRATEWPAN_REMOVEALL *, pOutBUf = NULL)
    SET_DOOR_WORK_MODE = 0x10013,               # 设置门锁工作模式(对应结构体pInBuf = NET_IN_CTRL_ACCESS_SET_DOOR_WORK_MODE *, pOutBUf = NULL)
    TEST_MAIL = 0x10014,                        # 测试邮件pInBuf = NET_IN_TEST_MAIL *, pOutBUf = NET_OUT_TEST_MAIL *
    CONTROL_SMART_SWITCH = 0x10015,             # 控制智能开关pInBuf = NET_IN_CONTROL_SMART_SWITCH *, pOutBUf = NET_OUT_CONTROL_SMART_SWITCH *
    LOWRATEWPAN_SETWORKMODE = 0x10016,          # 设置探测器的工作模式(对应结构体pInBuf=NET_IN_CTRL_LOWRATEWPAN_SETWORKMODE *, pOutBUf=NULL)
    COAXIAL_CONTROL_IO = 0x10017,               # 发送同轴IO控制命令(对应结构体pInBuf=NET_IN_CONTROL_COAXIAL_CONTROL_IO *, pOutBUf=NET_OUT_CONTROL_COAXIAL_CONTROL_IO *)
    START_REMOTELOWRATEWPAN_ALARMBELL = 0x10018,    # 开启无线警号(对应结构体pInBuf=NET_IN_START_REMOTELOWRATEWPAN_ALARMBELL *,pOutBUf=NET_OUT_START_REMOTELOWRATEWPAN_ALARMBELL *)
    STOP_REMOTELOWRATEWPAN_ALARMBELL = 0x10019, # 关闭无线警号(对应结构体pInBuf=NET_IN_STOP_REMOTELOWRATEWPAN_ALARMBELL *,pOutBUf=NET_OUT_STOP_REMOTELOWRATEWPAN_ALARMBELL *)
    THERMO_DO_FFC = 0x1001a,                    # 热成像FFC校准(对应结构体 pInBuf = NET_IN_THERMO_DO_FFC *,pOutBuf = NET_OUT_THERMO_DO_FFC *);Thermo FFC calibration(pInBuf = NET_IN_THERMO_DO_FFC *,pOutBuf = NET_OUT_THERMO_DO_FFC *);
    THERMO_FIX_FOCUS = 0x1001b,                 # 热成像双目定焦调(对应结构体 pInBuf = NET_IN_THERMO_FIX_FOCUS *,pOutBuf = NET_OUT_THERMO_FIX_FOCUS *);Thermo stereo fix focus(pInBuf = NET_IN_THERMO_FIX_FOCUS *,pOutBuf = NET_OUT_THERMO_FIX_FOCUS *);
    SET_THIRD_CALLSTATUS = 0x1001c,             # 设置对讲状态(对应结构体pInBuf = NET_IN_VTP_THIRDCALL_STATUS*, pOutBuf = NET_OUT_VTP_THIRDCALL_STATUS*);Set call status(pInBuf = NET_IN_VTP_THIRDCALL_STATUS*, pOutBuf = NET_OUT_VTP_THIRDCALL_STATUS*);
    ACCESS_CLEAR_STATUS = 0x1001d,              # 门禁-清除用户进出门状态 (对应结构体pInBuf = NET_IN_ACCESS_CLEAR_STATUS*, pOutBuf = NET_OUT_ACCESS_CLEAR_STATUS *);access control - clear out status (pInBuf = NET_IN_ACCESS_CLEAR_STATUS*, pOutBuf = NET_OUT_ACCESS_CLEAR_STATUS *);
    ACCESS_DEAL_RECORD = 0x1001e,               # 门禁-查询/设置用户进出门记录 (对应结构体pInBuf = NET_IN_ACCESS_DEAL_RECORD*, pOutBuf = NET_OUT_ACCESS_DEAL_RECORD*);access control - operate user entry or exit records (pInBuf = NET_IN_ACCESS_DEAL_RECORD*, pOutBuf = NET_OUT_ACCESS_DEAL_RECORD*);
    QUERY_DELIVERED_FILE = 0x1001f,             # 向视频输出口查询广告信息,楼宇对讲使用,(对应结构体pInBuf = NET_IN_CTRL_QUERY_DELIVERYE_FILE*, pOutBuf = NET_OUT_CTRL_QUERY_DELIVERYE_FILE*);Inquire advertising information from the video output port, and use building intercom(pInBuf = NET_IN_CTRL_QUERY_DELIVERYE_FILE*, pOutBuf = NET_OUT_CTRL_QUERY_DELIVERYE_FILE*);
    SET_PARK_CONTROL_INFO = 0x10020,            # 设置停车控制信息(点阵屏和语音播报的控制)(对应结构体pInBuf = NET_IN_SET_PARK_CONTROL_INFO*, pOutBuf = NET_OUT_SET_PARK_CONTROL_INFO*);Set Park control info(Control of dot matrix screen and voice broadcast)(pInBuf = NET_IN_SET_PARK_CONTROL_INFO*, pOutBuf = NET_OUT_SET_PARK_CONTROL_INFO*);
    CHANGE_SUSTAIN = 0x10021,                   # 修改图片广告文件的停留时间,(对应结构体pInBuf = NET_IN_CTRL_CHANGE_SUSTAIN*, pOutBuf = NET_OUT_CTRL_CHANGE_SUSTAIN*);Modify the dwell time of the image ad file,(pInBuf = NET_IN_CTRL_CHANGE_SUSTAIN*, pOutBuf = NET_OUT_CTRL_CHANGE_SUSTAIN*);
    DEVVIDEOINPUT_LIGHT = 0x10022,              # 控制灯光,(对应结构体pInBuf = NET_IN_CTRL_DEVVIDEOINPUT_LIGHT*, pOutBuf = NET_OUT_CTRL_DEVVIDEOINPUT_LIGHT*);Control Light,(pInBuf = NET_IN_CTRL_DEVVIDEOINPUT_LIGHTN*, pOutBuf = NET_OUT_CTRL_DEVVIDEOINPUT_LIGHT*);
    SNAP_TASK_ADD = 0x10023,                    # 下发抓图任务(对应结构体pInBuf = NET_IN_CTRL_SNAP_TASK_ADD*, pOutBuf = NET_OUT_CTRL_SNAP_TASK_ADD*);Send a snapshot task(pInBuf = NET_IN_CTRL_SNAP_TASK_ADD*, pOutBuf = NET_OUT_CTRL_SNAP_TASK_ADD*);
    QUERY_DELIVERED_FILE_EX = 0x10024,          # 向视频输出口查询广告信息扩展,楼宇对讲使用,(对应结构体pInBuf = NET_IN_CTRL_QUERY_DELIVERYE_FILE_EX*, pOutBuf = NET_OUT_CTRL_QUERY_DELIVERYE_FILE_EX*);Inquire advertising information from the video output port extern, and use building intercom(pInBuf = NET_IN_CTRL_QUERY_DELIVERYE_FILE_EX*, pOutBuf = NET_OUT_CTRL_QUERY_DELIVERYE_FILE_EX*);
    LOWRATEWPAN_GETWIRELESSDEVSIGNAL = 0x10100, # 获取无线设备信号强度(对应结构体 pInBuf = NET_IN_CTRL_LOWRATEWPAN_GETWIRELESSDEVSIGNAL *, pOutBuf = NET_OUT_CTRL_LOWRATEWPAN_GETWIRELESSDEVSIGNAL *)
    LOWRATEWPAN_SET_ACCESSORY_PARAM = 0x10101,  # 设置配件信息(对应结构体pInBuf = NET_IN_CTRL_LOWRATEWPAN_ACCESSORY_PARAM *,pOutBuf = NULL); set accessory param(pInBuf = NET_IN_CTRL_LOWRATEWPAN_ACCESSORY_PARAM *,pOutBuf = NULL)

class EM_ACCOUNT_PROTOCOL(IntEnum):
    """
    协议类型;协议类型
    """
    ACCOUNT_PROTOCOL_NORMAL = 0,                # 通用协议;normal protocal
    ACCOUNT_PROTOCOL_TTLV = 1,                  # TTLV协议;TTLV protocal

class EM_LOGIN_SPAC_CAP_TYPE(IntEnum):
    """
    登陆方式;Login mode
    """
    TCP = 0,                                    # TCP登陆, 默认方式;TCP login, default
    ANY = 1,                                    # 无条件登陆;No criteria login
    SERVER_CONN = 2,                            # 主动注册的登入;auto sign up login
    MULTICAST = 3,                              # 组播登陆;multicast login, default
    UDP = 4,                                    # UDP方式下的登入;UDP method login
    MAIN_CONN_ONLY = 6,                         # 只建主连接下的登入;only main connection login
    SSL = 7,                                    # SSL加密方式登陆;SSL encryption login
    INTELLIGENT_BOX = 9,                        # 登录智能盒远程设备;login IVS box remote device
    NO_CONFIG = 10,                             # 登录设备后不做取配置操作;login device do not config
    U_LOGIN = 11,                               # 用U盾设备的登入;USB key device login
    LDAP = 12,                                  # LDAP方式登录;LDAP login
    AD = 13,                                    # AD（ActiveDirectory）登录方式;AD, ActiveDirectory,  login
    RADIUS = 14,                                # Radius 登录方式;Radius  login
    SOCKET_5 = 15,                              # Socks5登陆方式;Socks5 login
    CLOUD = 16,                                 # 云登陆方式;cloud login
    AUTH_TWICE = 17,                            # 二次鉴权登陆方式;dual authentication loin
    TS = 18,                                    # TS码流客户端登陆方式;TS stream client login
    P2P = 19,                                   # 为P2P登陆方式;web private login
    MOBILE = 20,                                # 手机客户端登陆;mobile client login
    TLS_ADAPTER = 21,                           # 自适应tls加密;adapter tls login;
    TLS_COMPEL = 22,                            # 强制tls加密;compel tls login;
    TLS_MAIN_ONLY = 23,                         # 部分tls加密;Partial TLS encryption;
    INVALID = 24,                               # 无效的登陆方式;invalid login

class EM_LOGIN_TLS_TYPE(IntEnum):
    """
    登陆时TLS加密模式
    TLS encryption mode when logging in
    """
    EM_LOGIN_TLS_TYPE_NO_TLS = 0,               # 不走tls加密, 默认方式;Do not use TLS encryption, the default method;
    EM_LOGIN_TLS_TYPE_TLS_ADAPTER = 1,          # 自适应tls加密;Adaptive tls encryption;
    EM_LOGIN_TLS_TYPE_TLS_COMPEL = 2,           # 强制tls加密;force tls encryption;
    EM_LOGIN_TLS_TYPE_TLS_MAIN_ONLY = 3,        # 部分tls加密;Partial tls encryption;
    EM_LOGIN_TLS_TYPE_TLS_GENERAL = 4,          # 通用tls加密;General tls encryptions;

class SDK_RealPlayType(IntEnum):
    """
    预览类型, 对应RealPlayEx接口;Preview type.Corresponding to RealPlayEx
    """
    Realplay = 0,                               # 实时预览;Real-time preview
    Multiplay = 1,                              # 多画面预览;Multiple-channel preview
    Realplay_0 = 2,                             # 实时预览 - 主码流, 等同于Realplay;Real-time monitor-main stream. It is the same as DH_RType_Realplay
    Realplay_1 = 3,                             # 实时预览 - 从码流1;1 Real-time monitor -- extra stream 1
    Realplay_2 = 4,                             # 实时预览 - 从码流2;2 Real-time monitor -- extra stream 2
    Realplay_3 = 5,                             # 实时预览 - 从码流3;3 Real-time monitor -- extra stream 3
    Multiplay_1 = 6,                            # 多画面预览－1画面;Multiple-channel preview--1-window
    Multiplay_4 = 7,                            # 多画面预览－4画面;Multiple-channel preview--4-window
    Multiplay_8 = 8,                            # 多画面预览－8画面;Multiple-channel preview--8-window
    Multiplay_9 = 9,                            # 多画面预览－9画面;Multiple-channel preview--9-window
    Multiplay_16 = 10,                          # 多画面预览－16画面;Multiple-channel preview--16-window
    Multiplay_6 = 11,                           # 多画面预览－6画面;Multiple-channel preview--6-window
    Multiplay_12 = 12,                          # 多画面预览－12画面;Multiple-channel preview--12-window
    Multiplay_25 = 13,                          # 多画面预览－25画面;Multi-window tour--25-windows
    Multiplay_36 = 14,                          # 多画面预览－36画面;Multi-window preview--36-windows
    Multiplay_64 = 15,                          # 多画面预览－64画面;Multi-window preview--64-windows
    Multiplay_255 = 16,                         # 不修改当前预览通道数;Do not modify the current preview channel number
    Realplay_Test = 255,                        # 带宽测试码流;test stream

class EM_SEND_SEARCH_TYPE(IntEnum):
    """
    下发搜索类型,send search type
    """
    MULTICAST_AND_BROADCAST = 0,                # 组播和广播搜索;multicast and broadcast search
    MULTICAST = 1,                              # 组播搜索;multicast search
    BROADCAST = 2,                              # 广播搜索;broadcast search

class EM_VEHICLE_DIRECTION(IntEnum):
    """
    车辆方向; vehicle direction
    """
    UNKOWN = 0,                                 # 未知;unknown
    HEAD = 1,                                   # 车头;head
    TAIL = 2,                                   # 车尾;rear
    VEHBODYSIDE = 3,                            # 车身(侧面);Body (side)

class EM_OPEN_STROBE_STATE(IntEnum):
    """
    开闸状态;open strobe state
    """
    UNKOWN = 0,                                 # 未知状态;unknown
    CLOSE = 1,                                  # 关闸;close
    AUTO = 2,                                   # 自动开闸;auto open
    MANUAL = 3,                                 # 手动开闸;manual open

class EM_TIME_TYPE(IntEnum):
    """
    时间类型;time type
    """
    ABSLUTE = 0,                                # 绝对时间;absolute time
    RELATIVE = 1,                               # 相对时间, 相对于视频文件头帧为时间基点, 头帧对应于UTC(0000 - 00 - 00 00: 00:00)
                                                # Relative time, relative to the video file header frame as the time basis points, the first frame corresponding to the UTC (0000-00-00 00:00:00)

class EM_COLOR_TYPE(IntEnum):
    """
    颜色类型;color type
    """
    RED = 0,                                    # 红色
    YELLOW = 1,                                 # 黄色
    GREEN = 2,                                  # 绿色
    CYAN = 3,                                   # 青色
    BLUE = 4,                                   # 蓝色
    PURPLE = 5,                                 # 紫色
    BLACK = 6,                                  # 黑色
    WHITE = 7,                                  # 白色
    MAX = 8,

class EM_EVENT_FILETAG(IntEnum):
    """
    事件文件的文件标签类型;event file's tag type
    """
    ATMBEFOREPASTE = 1,                         # ATM贴条前;Before ATM Paste
    ATMAFTERPASTE = 2,                          # ATM贴条后;After ATM Paste

class EM_TRAFFICCAR_MOVE_DIRECTION(IntEnum):
    """
    交通车辆行驶方向类型;traffic car move direction type
    """
    UNKNOWN = 0,                                # 未知的;unknown
    STRAIGHT = 1,                               # 直行;straight
    TURN_LEFT = 2,                              # 左转;turn left
    TURN_RIGHT = 3,                             # 右转;turn right
    TURN_AROUND = 4,                            # 掉头;turn around

class EM_TRAFFICCAR_CAR_TYPE(IntEnum):
    """
    车辆类型;car type
    """
    UNKNOWN = 0,                                # 未知;Unknown
    TRUST_CAR = 1,                              # 允许名单车辆;trust car
    SUSPICIOUS_CAR = 2,                         # 禁止名单车辆;suspicious car
    NORMAL_CAR = 3,                             # 非允许名单且非禁止名单车辆;normal car

class EM_TRAFFICCAR_LANE_TYPE(IntEnum):
    """
    车道类型;Lane type
    """
    UNKNOWN = 0,                                # 未知;unknown
    NORMAL = 1,                                 # 普通车道;Normal
    NONMOTOR = 2,                               # 非机动车车道;Non-motor
    LIGHT_DUTY = 3,                             # 小型车车道;Light-Duty
    BUS = 4,                                    # 公交车车道;Bus
    EMERGENCY = 5,                              # 应急车道;Emergency
    DANGEROUS = 6,                              # 危险品车道;Dangerous
    TIDAL = 7,                                  # 潮汐车道;Tidal

class EM_NTP_STATUS(IntEnum):
    """
    NTP校时状态;NTP status
    """
    UNKNOWN = 0,                                # 未知;Unknown
    DISABLE = 1,                                # 不使能;unable
    SUCCESSFUL = 2,                             # 成功;Successful
    FAILED = 3,                                 # 失败;Failed

class EM_VEHICLE_TYPE(IntEnum):
    """
    收费站车型分类;Vehicle type inToll station
    """
    UNKNOWN = 0,                                # 未知
    PASSENGERCAR1 = 1,                          # 客1
    TRUCK1 = 2,                                 # 货1
    PASSENGERCAR2 = 3,                          # 客2
    TRUCK2 = 4,                                 # 货2
    PASSENGERCAR3 = 5,                          # 客3
    TRUCK3 = 6,                                 # 货3
    PASSENGERCAR4 = 7,                          # 客4
    TRUCK4 = 8,                                 # 货4
    PASSENGERCAR5 = 9,                          # 客5
    TRUCK5 = 10,                                # 货5

class EM_SNAPCATEGORY(IntEnum):
    """
    抓拍的类型;snap category
    """
    MOTOR = 0,                                  # 机动车;motor
    NONMOTOR = 1,                               # 非机动车;nonmotor

class EM_VEHICLE_TYPE_BY_FUNC(IntEnum):
    """
    按功能划分的车辆类型;vehicle type by function
    """
    UNKNOWN = 0,                                # 未知;unknown
                                                # 以下为特种车辆类型;special vehicle types follow
    TANK_CAR = 1,                               # 危化品车辆;tank car
    SLOT_TANK_CAR = 2,                          # 槽罐车;slot tank car
    DREGS_CAR = 3,                              # 渣土车;dregs car
    CONCRETE_MIXER_TRUCK = 4,                   # 混凝土搅拌车;concrete mixer truck
    TAXI = 5,                                   # 出租车;taxi
    POLICE = 6,                                 # 警车;police car
    AMBULANCE = 7,                              # 救护车;ambulance
    GENERAL = 8,                                # 普通车;general car
    WATERING_CAR = 9,                           # 洒水车;watering car
    FIRE_ENGINE = 10,                           # 消防车;fire engine
    MACHINESHOP_TRUCK = 11,                     # 工程车;machineshop truck
    POWER_LOT_VEHICLE = 12,                     # 粉粒物料车;power lot vehicle
    SUCTION_SEWAGE_TRUCK = 13,                  # 吸污车;suction sewage truck
    NORMAL_TANK_TRUCK = 14,                     # 普通罐车;normal tank truck
    SCHOOL_BUS = 15,                            # 校车;school bus
    EXCAVATOR = 16,                             # 挖掘机;exvavator
    BULLDOZER = 17,                             # 推土车;bulldozer
    CRANE = 18,                                 # 吊车;crane
    PUMP_TRUCK = 19,                            # 泵车;pump truck
    POULTRY = 20,                               # 禽畜车;Poultry;
    TRACTOR = 21,                               # 拖拉机;Tractor;

class EM_PLATE_ATTRIBUTE(IntEnum):
    """
    车牌属性
    Plate Attribute
    """
    EM_PLATE_ATTRIBUTE_UNKNOWN = 0,             # 未知;Unknown;
    EM_PLATE_ATTRIBUTE_NORMAL = 1,              # 正常;Normal;
    EM_PLATE_ATTRIBUTE_NO_PLATE = 2,            # 无牌;NoPlate;
    EM_PLATE_ATTRIBUTE_PARTIAL_OCCLUSION = 3,   # 部分遮挡/污损;PartialOcclusion;
    EM_PLATE_ATTRIBUTE_FULL_OCCLUSION = 4,      # 完全遮挡/污损;FullOcclusion;

class EM_STANDARD_VEHICLE_TYPE(IntEnum):
    """
    标准车辆类型;standard vehicle type
    """
    UNKNOWN = 0,                                # 未知
    MOTOR = 1,                                  # 机动车
    BUS = 2,                                    # 公交车
    UNLICENSED_MOTOR = 3,                       # 无牌机动车
    LARGE_CAR = 4,                              # 大型汽车
    MICRO_CAR = 5,                              # 小型汽车
    EMBASSY_CAR = 6,                            # 使馆汽车
    MARGINAL_CAR = 7,                           # 领馆汽车
    AREAOUT_CAR = 8,                            # 境外汽车
    FOREIGN_CAR = 9,                            # 外籍汽车
    FARM_TRANS_CAR = 10,                        # 农用运输车
    TRACTOR = 11,                               # 拖拉机
    TRAILER = 12,                               # 挂车
    COACH_CAR = 13,                             # 教练汽车
    TRIAL_CAR = 14,                             # 试验汽车
    TEMPORARYENTRY_CAR = 15,                    # 临时入境汽车
    TEMPORARYENTRY_MOTORCYCLE = 16,             # 临时入境摩托
    TEMPORARY_STEER_CAR = 17,                   # 临时行驶车
    LARGE_TRUCK = 18,                           # 大货车
    MID_TRUCK = 19,                             # 中货车
    MICRO_TRUCK = 20,                           # 小货车
    MICROBUS = 21,                              # 面包车
    SALOON_CAR = 22,                            # 轿车
    CARRIAGE = 23,                              # 小轿车
    MINI_CARRIAGE = 24,                         # 微型轿车
    SUV_MPV = 25,                               # SUV或者MPV
    SUV = 26,                                   # SUV
    MPV = 27,                                   # MPV
    PASSENGER_CAR = 28,                         # 客车
    MOTOR_BUS = 29,                             # 大客车
    MID_PASSENGER_CAR = 30,                     # 中客车
    MINI_BUS = 31,                              # 小客车
    PICKUP = 32,                                # 皮卡车
    OILTANK_TRUCK = 33,                         # 油罐车

class EM_OVERSEA_VEHICLE_CATEGORY_TYPE(IntEnum):
    """
    车辆类型中的子类别，一个车辆只能是子类型的某一种;subcategories of vehicle types
    """
    UNKNOWN = 0,                                # 未知;unknown
    MOTORCYCLE = 1,                             # 摩托车;motorcycle
    LIGHT_GOODS_VEHICLE = 2,                    # 轻型货车;light goods vehicle
    COMPANY_VEHICLE = 3,                        # 公司用私家车;company vehicle
    PRIVATE_VEHICLE = 4,                        # 个人用私家车;private vehicle
    TAXI = 5,                                   # TAXI或者快线车;taxi
    TRAILER = 6,                                # 拖车;trailer
    ENGINEERING_PLANT_VEHICLE = 7,              # 工程车;engineering plant vehicle
    VERY_HEAVY_GOODS_VEHICLE = 8,               # 超大货车;very heavy goods vehicle
    HEAVY_GOODS_VEHICLE = 9,                    # 大货车;heavy goods vehicle
    PUBLIC_BUS = 10,                            # 公共BUS;public bus
    PRIVATE_BUS = 11,                           # 私营BUS;private bus
    SPECIAL_VEHICLE = 12,                       # 特殊车辆;special vehicle

class EM_COMMON_SEAT_TYPE(IntEnum):
    """
    座驾类型;Seat type
    """
    UNKNOWN = 0,                                # 未识别
    MAIN = 1,                                   # 主驾驶
    SLAVE = 2,                                  # 副驾驶

class EM_A_NET_SAFEBELT_STATE(IntEnum):
    """
    安全带状态
    safe belt state
    """
    SS_NUKNOW = 0,                              # 未知;Unknow;
    SS_WITH_SAFE_BELT = 1,                      # 已系安全带;WithSafeBelt;
    SS_WITHOUT_SAFE_BELT = 2,                   # 未系安全带;WithoutSafeBelt;

class EM_A_NET_SUNSHADE_STATE(IntEnum):
    """
    遮阳板状态
    sun shade state
    """
    SS_NUKNOW_SUN_SHADE = 0,                    # 未知;Unknow;
    SS_WITH_SUN_SHADE = 1,                      # 有遮阳板;WithSunShade;
    SS_WITHOUT_SUN_SHADE = 2,                   # 无遮阳板;WithoutSunShade;

class NET_SAFEBELT_STATE(IntEnum):
    """
    安全带状态;Safe belt state
    """
    SS_NUKNOW = 0,                              # 未知;Unknown
    SS_WITH_SAFE_BELT = 1,                      # 已系安全带;with safe  belt
    SS_WITHOUT_SAFE_BELT = 2,                   # 未系安全带;without safe belt

class NET_SUNSHADE_STATE(IntEnum):
    """
    遮阳板状态; Sun shade state
    """
    SS_NUKNOW_SUN_SHADE = 0,                    # 未知;Unknown
    SS_WITH_SUN_SHADE = 1,                      # 有遮阳板;with sun shade
    SS_WITHOUT_SUN_SHADE = 2,                   # 无遮阳板;without sun shade

class EM_CALL_ACTION_TYPE(IntEnum):
    """
    打电话的动作类型
    Call action type
    """
    EM_CALL_ACTION_TYPE_UNKNOWN = 0,            # 未知;Unknown;
    EM_CALL_ACTION_TYPE_CALL_BY_EAR = 1,        # 贴耳;Call by ear;
    EM_CALL_ACTION_TYPE_CALL_HAND_HOLD = 2,     # 手持;Hold;

class EM_CARD_PROVINCE(IntEnum):
    """
    卡号省份;card province
    """
    UNKNOWN = 10,                               # 解析出错，未知省份;UNKNOWN
    BEIJING = 11,                               # 北京;BeiJing
    TIANJIN = 12,                               # 天津;TianJin
    HEBEI = 13,                                 # 河北;HeBei
    SHANXI_TAIYUAN = 14,                        # 山西;ShanXi, the provincial capital is TaiYuan
    NEIMENGGU = 15,                             # 内蒙古;NeiMengGu
    LIAONING = 21,                              # 辽宁;LiaoNing
    JILIN = 22,                                 # 吉林;JiKin
    HEILONGJIANG = 23,                          # 黑龙江;HeiLongJiang
    SHANGHAI = 31,                              # 上海;ShangHai
    JIANGSU = 32,                               # 江苏;JiangSu
    ZHEJIANG = 33,                              # 浙江;ZheJiang
    ANHUI = 34,                                 # 安徽;AnHui
    FUJIAN = 35,                                # 福建;FuJian
    JIANGXI = 36,                               # 江西;JiangXi
    SHANDONG = 37,                              # 山东;ShanDong
    HENAN = 41,                                 # 河南;HeNan
    HUBEI = 42,                                 # 湖北;HuBei
    HUNAN = 43,                                 # 湖南;HuNan
    GUANGDONG = 44,                             # 广东;GuangDong
    GUANGXI = 45,                               # 广西;GuangXi
    HAINAN = 46,                                # 海南;HaiNan
    CHONGQING = 50,                             # 重庆;ChongQing
    SICHUAN = 51,                               # 四川;SiChuan
    GUIZHOU = 52,                               # 贵州;GuiZhou
    YUNNAN = 53,                                # 云南;YunNan
    XIZANG = 54,                                # 西藏;XiZang
    SHANXI_XIAN = 61,                           # 陕西;ShanXi , the provincial capital is XiAn
    GANSU = 62,                                 # 甘肃;GanSu
    QINGHAI = 63,                               # 青海;QingHai
    NINGXIA = 64,                               # 宁夏;NingXia
    XINJIANG = 65,                              # 新疆;XinJiang
    XIANGGANG = 71,                             # 香港;XiangGang
    AOMEN = 82,                                 # 澳门;AoMen
    TAIWAN = 83,                                # 台湾;TaiWan

class EM_PLATE_TYPE(IntEnum):
    """
    号牌类型;the tpye of the plate
    """
    OTHER = 0,                                  # 其他车;Other
    BIG_CAR = 1,                                # 大型汽车;big car
    SMALL_CAR = 2,                              # 小型汽车;small car
    EMBASSY_CAR = 3,                            # 使馆汽车;embassy car
    CONSULATE_CAR = 4,                          # 领馆汽车;consulate car
    ABROAD_CAR = 5,                             # 境外汽车;abroad car
    FOREIGN_CAR = 6,                            # 外籍汽车;foreign car
    LOW_SPEED_CAR = 7,                          # 低速车;Low speed car
    COACH_CAR = 8,                              # 教练车;coach car plate
    MOTORCYCLE = 9,                             # 摩托车;motorcycle plate
    NEW_POWER_CAR = 10,                         # 新能源车;new power car
    POLICE_CAR = 11,                            # 警用车;police car
    HONGKONG_MACAO_CAR = 12,                    # 港澳两地车;Hongkong Macao car
    WJPOLICE_CAR = 13,
    OUTERGUARD_CAR = 14,
    TEMPORARY_LICENSE_FOR_NON_MOTOR_VEHICLES = 15,    # 非机动车临时牌照;Temporary license for non motor vehicles
    OFFICIAL_LICENSE_PLATE_FOR_NON_MOTOR_VEHICLE = 16,    # 非机动车牌正式牌照;Official license plate of non motor vehicle

class EM_CAR_COLOR_TYPE(IntEnum):
    """
    车身颜色;car color
    """
    WHITE = 0,                                  # 白色;white
    BLACK = 1,                                  # 黑色;black
    RED = 2,                                    # 红色;red
    YELLOW = 3,                                 # 黄色;yellow
    GRAY = 4,                                   # 灰色;gray
    BLUE = 5,                                   # 蓝色;blue
    GREEN = 6,                                  # 绿色;green
    PINK = 7,                                   # 粉色;pink
    PURPLE = 8,                                 # 紫色;purple
    DARK_PURPLE = 9,                            # 暗紫色;dark purple
    BROWN = 10,                                 # 棕色;brown
    MAROON = 11,                                # 粟色;marron
    SILVER_GRAY = 12,                           # 银灰色;silver gray
    DARK_GRAY = 13,                             # 暗灰色;dark gray;
    WHITE_SMOKE = 14,                           # 白烟色;white smoke;
    DEEP_ORANGE = 15,                           # 深橙色;deep orange
    LIGHT_ROSE = 16,                            # 浅玫瑰色;light rose
    TOMATO_RED = 17,                            # 番茄红色;tomato red
    OLIVE = 18,                                 # 橄榄色;olive
    GOLDEN = 19,                                # 金色;golden
    DARK_OLIVE = 20,                            # 暗橄榄色;dark olive
    YELLOW_GREEN = 21,                          # 黄绿色;yellow green
    GREEN_YELLOW = 22,                          # 绿黄色;green yellow
    FOREST_GREEN = 23,                          # 森林绿;forest green
    OCEAN_BLUE = 24,                            # 海洋绿;ocean blue
    DEEP_SKYBLUE = 25,                          # 深天蓝;deep sky blue
    CYAN = 26,                                  # 青色;cyan
    DEEP_BLUE = 27,                             # 深蓝色;deep blue
    DEEP_RED = 28,                              # 深红色;deep red
    DEEP_GREEN = 29,                            # 深绿色;deep green
    DEEP_YELLOW = 30,                           # 深黄色;deep yellow
    DEEP_PINK = 31,                             # 深粉色;deep pink
    DEEP_PURPLE = 32,                           # 深紫色;deep purple
    DEEP_BROWN = 33,                            # 深棕色;deep brown
    DEEP_CYAN = 34,                             # 深青色;deep cyan
    ORANGE = 35,                                # 橙色;orange
    DEEP_GOLDEN = 36,                           # 深金色;deep golden
    OTHER = 255,                                # 未识别、其他;other

class EM_USE_PROPERTY_TYPE(IntEnum):
    """
    使用性质;use property
    """
    NONOPERATING = 0,                           # 非营运;not operating
    HIGWAY = 1,                                 # 公路客运,旅游客运;higway,tourist
    BUS = 2,                                    # 公交客运;bus
    TAXI = 3,                                   # 出租客运;taxi
    FREIGHT = 4,                                # 货运;freight
    LEASE = 5,                                  # 租赁;lease
    SECURITY = 6,                               # 警用,消防,救护,工程救险;for police,for fire police,for rescue or engineering emergency
    COACH = 7,                                  # 教练;for coach
    SCHOOLBUS = 8,                              # 幼儿校车,小学生校车,其他校车;kindergarten school bus,pupil school bus,other school bus
    FOR_DANGE_VEHICLE = 9,                      # 危化品运输;for dangerous goods transportation
    OTHER = 10,                                 # 其他;Other
    ONLINE_CAR_HAILING = 11,                    # 网约车;Online car-hailing
    NON_MOTORIZED_TAKE_OUT_VEHICLE = 12,        # 非机动外卖车;Non motorized take out vehicle
    NON_MOTORIZED_EXPRESS_CAR = 13,             # 非机动快递车;Non motorized express car

class EM_NONMOTOR_OBJECT_STATUS(IntEnum):
    """
    事件/物体状态;things/objects status
    """
    UNKNOWN = 0,                                # 未识别;unknown
    NO = 1,                                     # 否;no
    YES = 2,                                    # 是;yes

class EM_EMOTION_TYPE(IntEnum):
    """
    表情;Emotion
    """
    UNKNOWN = 0,                                # 未知;unknown
    NORMAL = 1,                                 # 普通/正常;normal
    SMILE = 2,                                  # 微笑;smile
    ANGER = 3,                                  # 愤怒;anger
    SADNESS = 4,                                # 悲伤;sadness
    DISGUST = 5,                                # 厌恶;disgust
    FEAR = 6,                                   # 害怕;fear
    SURPRISE = 7,                               # 惊讶;surprise
    NEUTRAL = 8,                                # 正常;neutral
    LAUGH = 9,                                  # 大笑;laugh
    HAPPY = 10,                                 # 高兴;happy
    CONFUSED = 11,                              # 困惑;confused
    SCREAM = 12,                                # 尖叫;scream
    CALMNESS = 13,                              # 平静;calmness

class EM_CLOTHES_TYPE(IntEnum):
    """
    衣服类型;Clothes type
    """
    UNKNOWN = 0,                                # 未知;unknown
    LONG_SLEEVE = 1,                            # 长袖;long sleeve
    SHORT_SLEEVE = 2,                           # 短袖;short sleeve
    TROUSERS = 3,                               # 长裤;trousers
    SHORTS = 4,                                 # 短裤;shorts
    SKIRT = 5,                                  # 裙子;skirt
    WAISTCOAT = 6,                              # 背心;waistcoat
    MINIPANTS = 7,                              # 超短裤;mini-pants
    MINISKIRT = 8,                              # 超短裙;mini-skirt

class EM_OBJECT_COLOR_TYPE(IntEnum):
    """
    颜色类型;Color type
    """
    UNKNOWN = 0,                                # 未知;unknown
    WHITE = 1,                                  # 白色;white
    ORANGE = 2,                                 # 橙色;orange
    PINK = 3,                                   # 粉色;pink
    BLACK = 4,                                  # 黑色;black
    RED = 5,                                    # 红色;red
    YELLOW = 6,                                 # 黄色;yellow
    GRAY = 7,                                   # 灰色;gray
    BLUE = 8,                                   # 蓝色;blue
    GREEN = 9,                                  # 绿色;green
    PURPLE = 10,                                # 紫色;purple
    BROWN = 11,                                 # 棕色;purple
    SLIVER = 12,                                # 银色;sliver
    DARKVIOLET = 13,                            # 暗紫罗兰色;darkviolet
    MAROON = 14,                                # 栗色;maroon
    DIMGRAY = 15,                               # 暗灰色;dimgray
    WHITESMOKE = 16,                            # 白烟色;whitesmoke
    DARKORANGE = 17,                            # 深橙色;darkorange
    MISTYROSE = 18,                             # 浅玫瑰色;mistyrose
    TOMATO = 19,                                # 番茄红色;tomato
    OLIVE = 20,                                 # 橄榄色;olive
    GOLD = 21,                                  # 金色;gold
    DARKOLIVEGREEN = 22,                        # 暗橄榄绿色;darkolivegreen
    CHARTREUSE = 23,                            # 黄绿色;chartreuse
    GREENYELLOW = 24,                           # 绿黄色;green-yellow
    FORESTGREEN = 25,                           # 森林绿色;forest-green
    SEAGREEN = 26,                              # 海洋绿色;sea-green
    DEEPSKYBLUE = 27,                           # 深天蓝色;deepsky-blue
    CYAN = 28,                                  # 青色;cyan
    OTHER = 29,                                 # 无法识别;other

class EM_HAS_HAT(IntEnum):
    """
    是否戴帽子;Has hat
    """
    UNKNOWN = 0,                                # 未知;Unknown
    NO = 1,                                     # 不戴帽子;Not has hat
    YES = 2,                                    # 戴帽子;Has hat

class EM_CAP_TYPE(IntEnum):
    """
    帽子类型;Cap type
    """
    UNKNOWN = 0,                                # 未知;unknown
    ORDINARY = 1,                               # 普通帽子;ordinary
    HELMET = 2,                                 # 头盔;helmet
    SAFE = 3,                                   # 安全帽;safe hat

class EM_HAIR_STYLE(IntEnum):
    """
    头发样式;hair style
    """
    UNKNOWN = 0,                                # 未知
    LONG_HAIR = 1,                              # 长发
    SHORT_HAIR = 2,                             # 短发
    PONYTAIL = 3,                               # 马尾
    UPDO = 4,                                   # 盘发
    HEAD_BLOCKED = 5,                           # 头部被遮挡
    NONE = 6,                                   # 无头发

class EM_SEX_TYPE(IntEnum):
    """
    性别;sex
    """
    UNKNOWN = 0,                                # 未知;unknown
    MALE = 1,                                   # 男性;male
    FEMALE = 2,                                 # 女性;female

class EM_GLASSES_TYPE(IntEnum):
    """
    眼镜类型
    type of glassess
    """
    EM_GLASSES_UNKNOWN = 0,                     # 未知;unknown;
    EM_GLASSES_SUNGLASS = 1,                    # 太阳眼镜;sun glasses;
    EM_GLASSES_GLASS = 2,                       # 普通眼镜;normal galsses;

class EM_EYE_STATE_TYPE(IntEnum):
    """
    眼睛状态;eyes state
    """
    UNKNOWN = 0,                                # 未知;unknown
    NODISTI = 1,                                # 未识别;no disringuish
    CLOSE = 2,                                  # 闭眼;close eyes
    OPEN = 3,                                   # 睁眼;open eyes

class EM_MOUTH_STATE_TYPE(IntEnum):
    """
    嘴巴状态; mouth state type
    """
    UNKNOWN = 0,                                # 未知;Unknown
    NODISTI = 1,                                # 未识别;no disringuish
    CLOSE = 2,                                  # 闭嘴;close mouth
    OPEN = 3,                                   # 张嘴;open mouth

class EM_MASK_STATE_TYPE(IntEnum):
    """
    口罩状态;mask state type
    """
    UNKNOWN = 0,                                # 未知;unknown
    NODISTI = 1,                                # 未识别;no disringuish
    NOMASK = 2,                                 # 没戴口罩;no mask
    WEAR = 3,                                   # 戴口罩;wearing mask

class EM_BEARD_STATE_TYPE(IntEnum):
    """
    胡子状态;beard state type
    """
    UNKNOWN = 0,                                # 未知;unknown
    NODISTI = 1,                                # 未识别;no disringuish
    NOBEARD = 2,                                # 没胡子;no beard
    HAVEBEARD = 3,                              # 有胡子;have beard

class EM_HAS_GLASS(IntEnum):
    """
    是否带眼镜;Glasses state
    """
    UNKNOWN = 0,                                # unknown
    NO = 1,                                     # unwear
    NORMAL = 2,                                 # wear normal glasses
    SUN = 3,                                    # wear sun glasses
    BLACK = 4,                                  # wear black glasses

class EM_STRABISMUS_TYPE(IntEnum):
    """
    斜视状态;Strabismus type
    """
    UNKNOWN = 0,                                # 未知;unknown
    NORMAL = 1,                                 # 正常;normal
    YES = 2,                                    # 斜视;Strabismus

class EM_CLASS_TYPE(IntEnum):
    """
    大类业务方案;class type
    """
    UNKNOWN = 0,                                # 未知业务;unknown
    VIDEO_SYNOPSIS = 1,                         # 视频浓缩;video synopsis
    TRAFFIV_GATE = 2,                           # 卡口;traffic gate
    ELECTRONIC_POLICE = 3,                      # 电警;electronic police
    SINGLE_PTZ_PARKING = 4,                     # 单球违停;single ptz parking
    PTZ_PARKINBG = 5,                           # 主从违停;ptz parking
    TRAFFIC = 6,                                # 交通事件"Traffic";Traffic
    NORMAL = 7,                                 # 通用行为分析"Normal";Normal
    PS = 8,                                     # 行为分析
    ATM = 9,                                    # 金融行为分析"ATM";ATM
    METRO = 10,                                 # 地铁行为分析;metro
    FACE_DETECTION = 11,                        # 人脸检测"FaceDetection";FaceDetection
    FACE_RECOGNITION = 12,                      # 目标识别"TargetRecognition";TargetRecognition
    NUMBER_STAT = 13,                           # 人数统计"NumberStat";NumberStat
    HEAT_MAP = 14,                              # 热度图"HeatMap";HeatMap
    VIDEO_DIAGNOSIS = 15,                       # 视频诊断"VideoDiagnosis";VideoDiagnosis
    VIDEO_ENHANCE = 16,                         # 视频增强;video enhance
    SMOKEFIRE_DETECT = 17,                      # 烟火检测;smokefire detect
    VEHICLE_ANALYSE = 18,                       # 车辆特征识别"VehicleAnalyse";VehicleAnalyse
    PERSON_FEATURE = 19,                        # 人员特征识别;person feature
    SDFACEDETECTION = 20,                       # 多预置点人脸检测"SDFaceDetect";SDFaceDetect
                                                # 配置一条规则但可以在不同预置点下生效
    HEAT_MAP_PLAN = 21,                         # 球机热度图计划"HeatMapPlan";HeatMapPlan
    NUMBERSTAT_PLAN = 22,                       # 球机客流量统计计划 "NumberStatPlan";NumberStatPlan
    ATMFD = 23,                                 # 金融人脸检测，包括正常人脸、异常人脸、相邻人脸、头盔人脸等针对ATM场景特殊优化;ATM face detect
    HIGHWAY = 24,                               # 高速交通事件检测"Highway";Highway
    CITY = 25,                                  # 城市交通事件检测 "City";City
    LETRACK = 26,                               # 民用简易跟踪"LeTrack";LeTrack
    SCR = 27,                                   # 打靶相机"SCR";SCR
    STEREO_VISION = 28,                         # 立体视觉(双目)"StereoVision";StereoVision
    HUMANDETECT = 29,                           # 人体检测"HumanDetect";HumanDetect
    FACE_ANALYSIS = 30,                         # 人脸分析 "FaceAnalysis";FaceAnalysis
    EM_CALSS_XRAY_DETECTION = 31,               # X光检测 "XRayDetection";XRayDetection
    STEREO_NUMBER = 32,                         # 双目相机客流量统计 "StereoNumber";StereoNumber
    CROWDDISTRIMAP = 33,                        # 人群分布图;crowd distrimap
    OBJECTDETECT = 34,                          # 目标检测;object detect
    FACEATTRIBUTE = 35,                         # IVSS人脸检测 "FaceAttribute";FaceAttribute
    FACECOMPARE = 36,                           # IVSS目标识别 "FaceCompare";FaceCompare
    EM_CALSS_STEREO_BEHAVIOR = 37,              # 立体行为分析 "StereoBehavior";StereoBehavior
    EM_CALSS_INTELLICITYMANAGER = 38,           # 智慧城管 "IntelliCityMgr";IntelliCityMgr
    EM_CALSS_PROTECTIVECABIN = 39,              # 防护舱（ATM舱内）"ProtectiveCabin";ProtectiveCabin
    EM_CALSS_AIRPLANEDETECT = 40,               # 飞机行为检测 "AirplaneDetect";AirplaneDetect
    EM_CALSS_CROWDPOSTURE = 41,                 # 人群态势（人群分布图服务）"CrowdPosture";CrowdPosture
    PHONECALLDETECT = 42,                       # 打电话检测 "PhoneCallDetect";PhoneCallDetect
    SMOKEDETECTION = 43,                        # 烟雾检测 "SmokeDetection";SmokeDetection
    BOATDETECTION = 44,                         # 船只检测 "BoatDetection";BoatDetection
    SMOKINGDETECT = 45,                         # 吸烟检测 "SmokingDetect";SmokingDetect
    WATERMONITOR = 46,                          # 水利监测 "WaterMonitor";WaterMonitor
    GENERATEGRAPHDETECTION = 47,                # 生成图规则 "GenerateGraphDetection";GenerateGraphDetection
    TRAFFIC_PARK = 48,                          # 交通停车 "TrafficPark";TrafficPark
    OPERATEMONITOR = 49,                        # 作业检测 "OperateMonitor";OperateMonitor
    INTELLI_RETAIL = 50,                        # 智慧零售大类 "IntelliRetail";IntelliRetail
    CLASSROOM_ANALYSE = 51,                     # 教育智慧课堂"ClassroomAnalyse";ClassroomAnalyse
    FEATURE_ABSTRACT = 52,                      # 特征向量提取大类 "FeatureAbstract";FeatureAbstract
    FACEBODY_DETECT = 53,                       # 人体检测大类 "FaceBodyDetect";FaceBodyDetect
    FACEBODY_ANALYSE = 54,                      # 人体识别大类 "FaceBodyAnalyse";FaceBodyAnalyse
    VEHICLES_DISTRI = 55,                       # 车辆密度 "VehiclesDistri";VehiclesDistri
    INTELLI_BREED = 56,                         # 智慧养殖检测 "IntelliBreed";IntelliBreed
    INTELLI_PS = 57,                            # 行为分析 "IntelliPS";IntelliPS
    ELECTRIC_DETECT = 58,                       # 电力检测 "ElectricDetect";ElectricDetect
    RADAR_DETECT = 59,                          # 雷达检测 "RadarDetect";RadarDetect
    PARKINGSPACE = 60,                          # 车位检测大类 "ParkingSpace";ParkingSpace
    INTELLI_FINANCE = 61,                       # 智慧金融 "IntelliFinance";IntelliFinance
    CROWD_ABNORMAL = 62,                        # 人群异常检测 "CrowdAbnormal";CrowdAbnormal
    ANATOMY_TEMP_DETECT = 63,                   # 人温度智能检测 "AnatomyTempDetect";AnatomyTempDetect
    WEATHER_MONITOR = 64,                       # 天气监控 "WeatherMonitor";WeatherMonitor
    ELEVATOR_ACCESS_CONTROL = 65,               # 电梯门禁 "ElevatorAccessControl";"ElevatorAccessControl"
    BREAK_RULE_BUILDING = 66,                   # 违章建筑 "BreakRuleBuilding";"BreakRuleBuilding"
    FOREIGN_DETECT = 67,                        # 异物检测 "ForeignDetection";"ForeignDetection"
    PANORAMA_TRAFFIC = 68,                      # 全景交通 "PanoramaTraffic";"PanoramaTraffic"
    CONVEY_OR_BLOCK = 69,                       # 传送带阻塞 "ConveyorBlock";"ConveyorBlock"
    KITCHEN_ANIMAL = 70,                        # 厨房有害动物检测 "KitchenAnimal";"KitchenAnimal"
    ALLSEEINGEYE = 71,                          # 万物检测 "AllSeeingEye";"AllSeeingEye"
    INTELLI_FIRE_CONTROL = 72,                  # 智慧消防 "IntelliFireControl";"IntelliFireControl"
    CONVERYER_BELT = 73,                        # 传送带检测 "ConveyerBelt";"ConveyerBelt"
    INTELLI_LOGISTICS = 74,                     # 智慧物流 "IntelliLogistics";"IntelliLogistics"
    SMOKE_FIRE = 75,                            # 烟火检测"SmokeFire";"SmokeFire"
    OBJECT_MONITOR = 76,                        # 物品监控"ObjectMonitor";"ObjectMonitor"
    INTELLI_PARKING = 77,                       # 智能停车"IntelliParking";"IntelliParking"
    FIRE_CONTROL = 78,                          # 智慧消防 "FireControl";"FireControl"
    ANIMAL_DETECTION = 79,                      # 动物检测 "AnimalDetection";"AnimalDetection"
    FIRE_CONTROL_MONITOR = 80,                  # 火警检测 "FireControlMonitor";"FireControlMonitor"
    FISH_MONITOR = 81,                          # 鱼群检测 "FishMonitor";"FishMonitor";
    SHOPTRUCK_DETECT = 82,                      # 工程车检测“ShopTruckDetect”;"ShopTruckDetect";

class EM_PLATE_COLOR_TYPE(IntEnum):
    """
    车牌颜色;Plate color
    """
    UNKNOWN = 0,                                # 未知 "Unknown";Unknown
    OTHER = 1,                                  # 其他颜色 "Other";Other
    BLUE = 2,                                   # 蓝色 "Blue";Blue
    YELLOW = 3,                                 # 黄色 "Yellow";Yellow
    WHITE = 4,                                  # 白色 "White";White
    BLACK = 5,                                  # 黑色 "Black";Black
    RED = 6,                                    # 红色 "Red";Red
    GREEN = 7,                                  # 绿色 "Green";Green
    SHADOW_GREEN = 8,                           # 渐变绿 "ShadowGreen";ShadowGreen
    YELLOW_GREEN = 9,                           # 黄绿双拼 "YellowGreen";YellowGreen
    YELLOW_BOTTOM_BLACK_TEXT = 10,              # 黄底黑字 "YellowbottomBlackText"
    BLUE_BOTTOM_WHITE_TEXT = 11,                # 蓝底白字 "BluebottomWhiteText"
    BLACK_BOTTOM_WHITE_TEXT = 12,               # 黑底白字 "BlackBottomWhiteText"

class EM_OBJECT_NONMOTORANGLE_TYPE(IntEnum):
    """
    非机动车的角度
    Non Motor vehicle angle
    """
    UNKNOWN = 0,                                # 未知;unknown;
    FRONT = 1,                                  # 正面;front;
    SIDE = 2,                                   # 侧面;side;
    BEHIND = 3,                                 # 后面;behind;

class EM_OBJECT_BASKET_TYPE(IntEnum):
    """
    非机动车车篮
    Non Motor vehicle basket
    """
    EM_OBJECT_BASKET_UNKNOWN = 0,               # 未知;unknown;
    EM_OBJECT_BASKET_NO = 1,                    # 无;no;
    EM_OBJECT_BASKET_YES = 2,                   # 有;yes;

class EM_OBJECT_STORAGEBOX_TYPE(IntEnum):
    """
    非机动车后备箱
    Non Motor vehicle StorageBox
    """
    EM_OBJECT_STORAGEBOX_UNKNOWN = 0,           # 未知;unknown;
    EM_OBJECT_STORAGEBOX_NO = 1,                # 无后备箱;no;
    EM_OBJECT_STORAGEBOX_OWNBOX = 2,            # 自带箱;own Box;
    EM_OBJECT_STORAGEBOX_SELFPACK = 3,          # 自装箱;self Packing Box;
    EM_OBJECT_STORAGEBOX_ALL = 4,               # 自装箱和自带箱都有;both ownBox and self Packing Box;

class EM_RAIN_SHED_TYPE(IntEnum):
    """
    雨棚（伞）类型
    Canopy (umbrella) type
    """
    EM_RAIN_SHED_TYPE_NONE = -1,                # 无;none;
    EM_RAIN_SHED_TYPE_NO_UMBRELLA = 0,          # 不撑伞;no umbrella;
    EM_RAIN_SHED_TYPE_NOT_PEOPLE_HOLD = 1,      # 人非手撑伞;People don't hold umbrellas;
    EM_RAIN_SHED_TYPE_UNKOWN = 2,               # 未知;unknow;
    EM_RAIN_SHED_TYPE_NO_MOTOR_UMBRELLA = 3,    # 非机动车装载雨伞;Non motor vehicle loading umbrella;
    EM_RAIN_SHED_TYPE_NO_MOTOR_CANOPY = 4,      # 非机动车装载雨棚;Non motor vehicle loading canopy;

class EM_USEDEV_MODE(IntEnum):
    """
    对讲方式； Audio talk way
    """
    TALK_CLIENT_MODE = 0,                       # 设置客户端方式进行语音对讲； Set client-end mode to begin audio talk
    TALK_SERVER_MODE = 1,                       # 设置服务器方式进行语音对讲； Set server mode to begin audio talk
    TALK_ENCODE_TYPE = 2,                       # 设置语音对讲编码格式(对应DHDEV_TALKDECODE_INFO)； Set encode format for audio talk
    ALARM_LISTEN_MODE = 3,                      # 设置报警订阅方式； Set alarm subscribe way
    CONFIG_AUTHORITY_MODE = 4,                  # 设置通过权限进行配置管理； Set user right to realize configuration management
    TALK_TALK_CHANNEL = 5,                      # 设置对讲通道(0~MaxChannel-1)； set talking channel(0~MaxChannel-1)
    RECORD_STREAM_TYPE = 6,                     # 设置待查询及按时间回放的录像码流类型(0-主辅码流,1-主码流,2-辅码流)； set the stream type of the record for query(0-both main and extra stream,1-only main stream,2-only extra stream)
    TALK_SPEAK_PARAM = 7,                       # 设置语音参数,对应结构体 NET_SPEAK_PARAM； set speaking parameter,corresponding to NET_SPEAK_PARAM
    RECORD_TYPE = 8,                            # 设置按时间录像回放及下载的录像文件类型(详见NET_RECORD_TYPE)； Set by time video playback and download the video file TYPE (see.net RECORD TYPE)
    TALK_MODE3 = 9,                             # 设置三代设备的语音对讲参数, 对应结构体 NET_TALK_EX； Set voice intercom parameters of three generations of equipment and the corresponding structure NET_TALK_EX
    PLAYBACK_REALTIME_MODE = 10,                # 设置实时回放功能(0-关闭,1开启)； set real time playback function(0-off, 1-on)
    TALK_TRANSFER_MODE = 11,                    # 设置语音对讲是否为转发模式, 对应结构体 NET_TALK_TRANSFER_PARAM； Judge the voice intercom if it was a forwarding mode, (corresponding to  NET_TALK_TRANSFER_PARAM)
    TALK_VT_PARAM = 12,                         # 设置VT对讲参数, 对应结构体 NET_VT_TALK_PARAM； Set VT Talk param (corresponding to  NET_VT_TALK_PARAM)
    TARGET_DEV_ID = 13,                         # 设置目标设备标示符, 用以查询新系统能力(非0-转发系统能力消息)； set target device identifier for searching system capacity information, (not zero - locate device forwards the information)
    AUDIO_RECORD_LENGTH = 15,                   # 设置录音缓存, 对应为一个int； set audio record length, corresponding to a int

class EM_STREAM_TYPE(IntEnum):
    """
    码流类型； stream type
    """
    UNKNOWN = 0,                                # 未知状态； unknown
    MAIN = 1,                                   # 主码流； main
    EXTRA1 = 2,                                 # 辅码流1； extra1
    EXTRA2 = 3,                                 # 辅码流2； extra2
    EXTRA3 = 4,                                 # 辅码流3； extra3

class EM_QUERY_RECORD_TYPE(IntEnum):
    """
    录像查询类型； Type of video search
    """
    ALL = 0,                                    # 所有录像; All the recorded video
    ALARM = 1,                                  # 外部报警录像; The video of external alarm
    MOTION_DETECT = 2,                          # 动态检测报警录像; The video of dynamic detection alarm
    ALARM_ALL = 3,                              # 所有报警录像; All the alarmed video
    CARD = 4,                                   # 卡号查询; query by the card number
    CONDITION = 5,                              # 按条件查询; query by condition
    JOIN = 6,                                   # 组合查询; combination query
    CARD_PICTURE = 8,                           # 按卡号查询图片, HB - U、NVS等使用; query pictures by the card number, used by HB-U,NVS
    PICTURE = 9,                                # 查询图片, HB - U、NVS等使用; query pictures, used by HB-U,NVS
    FIELD = 10,                                 # 按字段查询; query by field
    INTELLI_VIDEO = 11,                         # 智能录像查询; Smart record search
    NET_DATA = 15,                              # 查询网络数据, 金桥网吧等使用; query network data, used by Jinqiao Internet Bar
    TRANS_DATA = 16,                            # 查询透明串口数据录像; query the video of serial data
    IMPORTANT = 17,                             # 查询重要录像; query the important video
    TALK_DATA = 18,                             # 查询录音文件; query the recording file
    POS = 19,                                   # POS录像; query the pos record
    INVALID = 256,                              # 无效的查询类型; invalid query type

class EM_DEV_CFG_TYPE(IntEnum):
    """
    配置类型,GetDevConfig和SetDevConfig使用； Configuration type，used by GetDevConfig and SetDevConfig
    """
    DEVICECFG = 0x0001,                         # 设备属性配置 对应结构体 DHDEV_SYSTEM_ATTR_CFG; Device property configuration, Corresponding structure DHDEV_SYSTEM_ATTR_CFG
    TIMECFG = 0x0008,                           # DVR时间配置 对应结构体 NET_TIME; DVR time setup
    NTP_CFG = 0x001D,                           # NTP配置 对应结构体 NET_A_DEV_NTP_CFG; NTP config, Corresponding structure NET_A_DEV_NTP_CFG
    NETCFG_EX = 0x005b,                         # 网络扩展配置(对应结构体 NET_A_DEV_NET_CFG_EX); Network extension configuration (corresponding structure NET_A_DEV_NET_CFG_EX)

class EM_MOTION_DETECT_TYPE(IntEnum):
    """
    动检触发类型；Type of triggeing motion detection
    """
    UNKNOWN = 0,                                # 未知;unknown
    HUMAN = 1,                                  # 人;human
    VEHICLE = 2,                                # 车;vechicle
    HUMAN_AND_VEHICLE = 3,                      # 人和车;human and vechicle

class EM_DEV_EVENT_FACEDETECT_SEX_TYPE(IntEnum):
    """
    人脸检测对应性别类型；sex type of dectected human face
    """
    UNKNOWN = 0,                                # 未知;unknown
    MAN = 1,                                    # 男性;male
    WOMAN = 2,                                  # 女性;female

class EM_FACE_DETECT_STATUS(IntEnum):
    """
    人脸在摄像机画面中的状态；the status of person in camera picture
    """
    UNKNOWN = 0,                                # 未知;unknown
    APPEAR = 1,                                 # 出现;appear
    INPICTURE = 2,                              # 在画面中;in picture
    EXIT = 3,                                   # 离开;exit

class EM_HUMAN_TEMPERATURE_UNIT(IntEnum):
    """
    人体测温温度单位；Temperature unit of human temperature detection
    """
    UNKNOWN = -1,                               # 未知;unknown
    CENTIGRADE = 0,                             # 摄氏度;Centigrade
    FAHRENHEIT = 1,                             # 华氏度;Fahrenheit
    KELVIN = 2,                                 # 开尔文;Kelvin

class EM_PERSON_FEATURE_STATE(IntEnum):
    """
    人员建模状态；person feature state
    """
    UNKNOWN = 0,                                # 未知;unknown
    FAIL = 1,                                   # 建模失败,可能是图片不符合要求,需要换图片;failed to model, need to change the picture
    USEFUL = 2,                                 # 有可用的特征值;success to model, the data can be used for target recognition
    CALCULATING = 3,                            # 正在计算特征值;under calculating
    UNUSEFUL = 4,                               # 已建模，但算法升级导致数据不可用，需要重新建模;once modeling was successful, but became unusable after upgrading, need to abstract

class EM_REGISTER_DB_TYPE(IntEnum):
    """
    注册库属性；the type of register face DB
    """
    UNKNOWN = 0,                                # 未知;unknown
    NORMAL = 1,                                 # 普通库;normal
    BLACKLIST = 2,                              # 阻止名单;Block list
    WHITELIST = 3,                              # 允许名单;Allow list
    VIP = 4,
    STAFF = 5,                                  # 员工库;staff DB
    LEADER = 6,                                 # 领导库;leader DB

class EM_NEEDED_PIC_RETURN_TYPE(IntEnum):
    """
    查询结果返回图片的格式
    the format of the image returned in the query results
    """
    EM_NEEDED_PIC_TYPE_UNKOWN = 0,              # 未知类型;unknow;
    EM_NEEDED_PIC_TYPE_HTTP_URL = 1,            # 返回图片HTTP链接;http url;
    EM_NEEDED_PIC_TYPE_BINARY_DATA = 2,         # 返回图片二进制数据;binary data;
    EM_NEEDED_PIC_TYPE_HTTP_AND_BINARY = 3,     # 返回二进制和HTTP链接;http url and binary data;

class EM_CLOTHES_COLOR(IntEnum):
    """
    衣服颜色；Clothes color
    """
    UNKNOWN = 0,                                # 未知;unknown
    WHITE = 1,                                  # 白色;White
    ORANGE = 2,                                 # 橙色;Orange
    PINK = 3,                                   # 粉色;Pink
    BLACK = 4,                                  # 黑色;Black
    RED = 5,                                    # 红色;Red
    YELLOW = 6,                                 # 黄色;Yellow
    GRAY = 7,                                   # 灰色;Gray
    BLUE = 8,                                   # 蓝色;Blue
    GREEN = 9,                                  # 绿色;Green
    PURPLE = 10,                                # 紫色;Purple
    BROWN = 11,                                 # 棕色;Brown
    DARKORANGE = 12,                            # 深橙色;Dark orange
    OTHER = 13,                                 # 其他颜色(该选项设备协议已不支持, 此处为了兼容保留);Other (This option is no longer supported by device protocol. It is reserved here for compatibility);
    SILVER = 14,                                # 银色;Sliver;
    DARKVIOLET = 15,                            # 暗紫罗兰色;Dark violet;
    MARRON = 16,                                # 栗色;Marron;
    DIMGRAY = 17,                               # 暗灰色;Dimgray;
    WHITESMOKE = 18,                            # 白烟色;White smoke;
    MISTYROSE = 19,                             # 浅玫瑰色;Mistyr rose;
    TOMATO = 20,                                # 番茄红色;Tomato;
    OLIVE = 21,                                 # 橄榄色;Olive;
    GLOD = 22,                                  # 金色;Glod;
    DARKOLIVEGREEN = 23,                        # 暗橄榄绿色;Dark lolive green;
    CHARTREUSE = 24,                            # 黄绿色;Chartreuse;
    GREENYELLOW = 25,                           # 绿黄色;Green yellow;
    FORESTGREEN = 26,                           # 森林绿色;Forest green;
    SEAGREEN = 27,                              # 海洋绿色;Sea green;
    DEEPSKYBLUE = 28,                           # 深天蓝色;Deep sky blue;
    CYAN = 29,                                  # 青色;Cyan;
    LIGHTGREEN = 30,                            # 浅绿色;Light green;

class EM_COAT_TYPE(IntEnum):
    """
    上衣类型；coat type
    """
    UNKNOWN = 0,                                # 未知;unknown
    LONG_SLEEVE = 1,                            # 长袖;Long sleeve
    COTTA = 2,                                  # 短袖;Cotta
    SLEEVELESS = 3,                             # 无袖;Sleeveless

class EM_TROUSERS_TYPE(IntEnum):
    """
    裤子类型；Trousers type
    """
    UNKNOWN = 0,                                # 未知;unknown
    TROUSERS = 1,                               # 长裤;Trousers
    SHORTS = 2,                                 # 短裤;Shorts
    SKIRT = 3,                                  # 裙子;Skirt

class EM_HAS_BAG(IntEnum):
    """
    是否戴包(包括背包或拎包)；Has bag
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 不带包;No bag
    YES = 2,                                    # 带包;Has bag

class EM_ANGLE_TYPE(IntEnum):
    """
    角度；Angle
    """
    UNKNOWN = 0,                                # 未知;unknown
    FRONT = 1,                                  # 正面;front
    SIDE = 2,                                   # 侧面;side
    BACK = 3,                                   # 背面;back

class EM_HAS_UMBRELLA(IntEnum):
    """
    是否打伞；Umbrella state
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 未打伞;no umbrella
    YES = 2,                                    # 打伞;has umbrella

class EM_HAS_VEST(IntEnum):
    """
    是否有反光背心
    Is there a reflective vest
    """
    EM_HAS_VEST_UNKNOWN = 0,                    # 未知;UNKNOWN;
    EM_HAS_VEST_NO = 1,                         # 无;NO;
    EM_HAS_VEST_YES = 2,                        # 有;YES;

class EM_HAS_BADGE(IntEnum):
    """
    是否佩戴工牌
    Whether to wear a badge
    """
    EM_HAS_BADGE_UNKNOWN = 0,                   # 未知;UNKNOWN;
    EM_HAS_BADGE_NO = 1,                        # 无;NO;
    EM_HAS_BADGE_YES = 2,                       # 有;YES;

class EM_HAS_BABYCARRIAGE(IntEnum):
    """
    是否推婴儿车
    Whether to push a baby carriage
    """
    EM_HAS_BABYCARRIAGE_UNKNOWN = 0,            # 未知;UNKNOWN;
    EM_HAS_BABYCARRIAGE_NO = 1,                 # 无;NO;
    EM_HAS_BABYCARRIAGE_YES = 2,                # 有;YES;

class EM_IS_ERRORDETECT(IntEnum):
    """
    是否虚检
    Whether is error detect or not
    """
    EM_IS_ERRORDETECT_UNKNOWN = -1,             # 未知;UNKNOWN;
    EM_IS_ERRORDETECT_NO = 0,                   # 无;NO;
    EM_IS_ERRORDETECT_YES = 1,                  # 有;YES;

class EM_HAS_DOWNBODY(IntEnum):
    """
    人体部位是否有下半身
    Whether has down body
    """
    EM_HAS_DOWNBODY_UNKNOWN = -1,               # 未知;UNKNOWN;
    EM_HAS_DOWNBODY_NO = 0,                     # 无;NO;
    EM_HAS_DOWNBODY_YES = 1,                    # 有;YES;

class EM_COORDINATE_TYPE(IntEnum):
    """
    坐标系类型
    Coordinate type
    """
    EM_COORDINATE_TYPE_UNKNOWN = 0,             # 未知;Unknown;
    EM_COORDINATE_TYPE_ABSOLUTE = 1,            # 绝对坐标;Absolute coordinates;
    EM_COORDINATE_TYPE_8192 = 2,                # 8192坐标;8192 coordinate system;

class EM_HAS_HEAD(IntEnum):
    """
    人体部位是否有头
    Whether has head
    """
    EM_HAS_HEAD_UNKNOWN = -1,                   # 未知;UNKNOWN;
    EM_HAS_HEAD_NO = 0,                         # 无;NO;
    EM_HAS_HEAD_YES = 1,                        # 有;YES;

class EM_BAG_TYPE(IntEnum):
    """
    包类型；bag type
    """
    UNKNOWN = 0,                                # 未知;unknown
    HANDBAG = 1,                                # 手提包;hand bag
    SHOULDERBAG = 2,                            # 肩包;shoulder bag
    KNAPSACK = 3,                               # 背包;knapsack
    DRAWBARBOX = 4,                             # 拉杆箱;drawar box
    WAISTPACK = 5,                              # 腰包;waist pack
    NONE = 6,                                   # 无包;no bag

class EM_CLOTHES_PATTERN(IntEnum):
    """
    衣服图案；clothes pattern
    """
    UNKNOWN = 0,                                # 未知;unknown
    PURE = 1,                                   # 纯色;pure color
    STRIPE = 2,                                 # 条纹;Stripe
    PATTERN = 3,                                # 图案;Pattern
    GAP = 4,                                    # 缝隙;Gap
    LATTICE = 5,                                # 格子;Lattice
    SPLITJOIN = 6,                              # 拼接;split join
    FLORAL = 7,                                 # 碎花;floral

class EM_UNIFORM_STYLE(IntEnum):
    """
    制服样式
    Uniform style
    """
    UNKNOWN = 0,                                # 未知;Unknown;
    POLICE = 1,                                 # 警服;Police uniform;
    NOUNIFORM = 2,                              # 无制服;No uniform;
    SINOPEC = 3,                                # 中石化制服;Sinopec uniform;
    GUARD = 4,                                  # 防护服;Protective uniform;
    VEST = 5,                                   # 马甲;Vest;
    SATNITATION = 6,                            # 环卫服;Sanitation uniform;
    TAKEOUT = 7,                                # 外卖服;Takeout uniform;
    JUN = 8,                                    # 军装;Mltry uniform;
    EXPRESS = 9,                                # 快递服;Express uniform;
    SECURITY = 10,                              # 保安服;Security uniform;

class EM_HAS_BACK_BAG(IntEnum):
    """
    是否有背包；Has back bag or not
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 没有背包;No back bag
    YES = 2,                                    # 有背包;Has back bag

class EM_HAS_CARRIER_BAG(IntEnum):
    """
    是否有手提包；Has carrier bag or not
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 没有手提包;No carrier bag
    YES = 2,                                    # 有手提包;Has carrier bag

class EM_HAS_SHOULDER_BAG(IntEnum):
    """
    是否有肩包；Has shoulder bag or not
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 没有肩包;No shoulder bag
    YES = 2,                                    # 有肩包;Has shoulder bag

class EM_HAS_MESSENGER_BAG(IntEnum):
    """
    是否有斜挎包；Has messenger bag or not
    """
    UNKNOWN = 0,                                # 未知;unknown
    NO = 1,                                     # 没有斜挎包;No messenger bag
    YES = 2,                                    # 有斜挎包;Has messenger bag

class EM_PIC_OPERATE_TYPE(IntEnum):
    """
    图片操作类型
    Picture operation type
    """
    EM_PIC_OPERATE_UNKNOWN = 0,                 # 未知;Unknown;
    EM_PIC_OPERATE_MODIFY = 1,                  # 修改;Modify;
    EM_PIC_OPERATE_ADD = 2,                     # 新增;Add;
    EM_PIC_OPERATE_DEL = 3,                     # 删除;Delete;

class EM_FREQUENCY_ALARM_TYPE(IntEnum):
    """
    报警类型
    alarm type
    """
    EM_FREQUENCY_ALARM_UNKNOWN = -1,            # 未知;unknown;
    EM_FREQUENCY_ALARM_HIGH = 0,                # 高频报警;high frequency;
    EM_FREQUENCY_ALARM_LOW = 1,                 # 低频报警;low frequency;

class EM_FACE_APPEND_STATE(IntEnum):
    """
    人脸导入的状态
    Face append state
    """
    EM_FACE_APPEND_STATE_UNKNOWN = 0,           # 未知;unknown;
    EM_FACE_APPEND_STATE_START = 1,             # 开始导入;Start import;
    EM_FACE_APPEND_STATE_RUN = 2,               # 正在导入;Importing;
    EM_FACE_APPEND_STATE_STOP = 3,              # 导入结束;Stop import;
    EM_FACE_APPEND_STATE_CANCLE = 4,            # 导入取消;Cancle import;

class EM_OBJECT_TYPE(IntEnum):
    """
    对象目标类型；Has messenger bag or not
    """
    UNKNOWN = -1,                               # 未知;unknown
    FACE = 0,                                   # 人脸;Face
    HUMAN = 1,                                  # 人体;Human
    VECHILE = 2,                                # 机动车;Vechile
    NOMOTOR = 3,                                # 非机动车;Nomotor
    ALL = 4,                                    # 所有类型;All

class EM_MULTIFACE_DETECT_ERRCODE(IntEnum):
    """
    大图检测小图结果错误码
    Error code of multi detect in scene image
    """
    EM_MULTIFACE_DETECT_UNKNOWN = -1,           # 未知;Unknown;
    EM_MULTIFACE_DETECT_SUCCESS = 0,            # 成功;Success;
    EM_MULTIFACE_DETECT_DECODE_FAIL = 1,        # 解码失败;Decode fail;
    EM_MULTIFACE_DETECT_NO_OBJECT = 2,          # 未检测到有效目标;No effect object;

class EM_PERSON_FEATURE_ERRCODE(IntEnum):
    """
    建模失败原因；error code of person feature
    """
    UNKNOWN = 0,                                # 未知;unknown
    PIC_FORMAT = 1,                             # 图片格式问题;invalid picture format
    NO_FACE = 2,                                # 无人脸或不清晰;no face or unclear face
    MULTI_FACE = 3,                             # 多个人脸;multi face
    PIC_DECODE_FAIL = 4,                        # 图片解码失败;picture decoding failed
    NOT_RECOMMEND = 5,                          # 不推荐入库;not recommended for storage
    FACEDB_FAIL = 6,                            # 数据库操作失败;failure of database operation
    GET_PICTURE = 7,                            # 获取图片失败;fail to ge picture
    SYSTEM_ERROR = 8,                           # 系统异常;system error

class EM_REALDATA_FLAG(IntEnum):
    """
    实时预览的实时数据标志, 对应 CLIENT_SetRealDataCallBackEx(Ex2) 中的 dwFlag 参数；real data flag, corresponding param dwFlag in CLIENT_SetRealDataCallBackEx
    支持 '|' 运算符, 如 dwFlag = REALDATA_FLAG_RAW_DATA | REALDATA_FLAG_YUV_DATA； supports '|' operator, like dwFlag = REALDATA_FLAG_RAW_DATA | REALDATA_FLAG_YUV_DATA
    """
    RAW_DATA = 0x01,                            # 原始数据标志,           对应fRealDataCallBack(Ex/Ex2)回调函数中 dwDataType 为0, 0x01 = 0x01 << 0; raw data flag,		        corresponding param dwDataType in fRealDataCallBack / fRealDataCallBackEx is 0, 0x01 = 0x01 << 0
    DATA_WITH_FRAME_INFO = 0x02,                # 带有帧信息的数据标志,   对应fRealDataCallBack(Ex/Ex2)回调函数中 dwDataType 为1, 0x02 = 0x01 << 1; data with frame info flag,	corresponding param dwDataType in fRealDataCallBack / fRealDataCallBackEx is 1, 0x02 = 0x01 << 1
    YUV_DATA = 0x04,                            # YUV 数据标志,           对应fRealDataCallBack(Ex/Ex2)回调函数中 dwDataType 为2, 0x04 = 0x01 << 2; YUV data flag,		        corresponding param dwDataType in fRealDataCallBack / fRealDataCallBackEx is 2, 0x04 = 0x01 << 2
    PCM_AUDIO_DATA = 0x08,                      # PCM 音频数据标志,       对应fRealDataCallBack(Ex/Ex2)回调函数中 dwDataType 为3, 0x08 = 0x01 << 3; PCM audio data flag,	    corresponding param dwDataType in fRealDataCallBack / fRealDataCallBackEx is 3, 0x08 = 0x01 << 3

class EM_CAMERA_STATE_TYPE(IntEnum):
    """
    连接状态；Camera connect state
    """
    UNKNOWN = 0,                                # 未知;unknown
    CONNECTING = 1,                             # 正在连接;connecting
    CONNECTED = 2,                              # 已连接;connected
    UNCONNECT = 3,                              # 未连接;unconnected
    EMPTY = 4,                                  # 通道未配置,无信息;channel is not configured, no info
    DISABLE = 5,                                # 通道有配置,但被禁用;channel is configured, but it is forbidden
    CAMERA_STATE_TYPE_UNINITED = 6,             # 前端未初始化;UnInited
    CAMERA_STATE_TYPE_HIBERNATION = 7,          # 休眠;Hibernation

class EM_COMM_ATTACHMENT_TYPE(IntEnum):
    """
    车辆物件类型;Common attachment type
    """
    UNKNOWN = 0,                                # 未知类型;Unknown type
    FURNITURE = 1,                              # 摆件;Furniture
    PENDANT = 2,                                # 挂件;Pendant
    TISSUEBOX = 3,                              # 纸巾盒;TissueBox
    DANGER = 4,                                 # 危险品;Danger
    PERFUMEBOX = 5,                             # 香水;perfumebox

class EM_TRAFFIC_VEHICLE_ACTION(IntEnum):
    """
    车辆行为类型;Vehicle behavior type
    """
    TRAFFIC_VEHICLE_ACTION_UNKNOWN = 0,         # 未知;Unknwon
    TRAFFIC_VEHICLE_ACTION_WOOD = 1,            # 伐木盗林;Logging and stealing forests
    TRAFFIC_VEHICLE_ACTION_STONE = 2,           # 偷盗沙石;Stealing sand and stones

class EM_CATEGORY_NONMOTOR_TYPE(IntEnum):
    """
    非机动车子类型;nomotor type
    """
    UNKNOWN = 0,                                # 未知;unknown
    TRICYCLE = 1,                               # 三轮车;Tricycle
    MOTORCYCLE = 2,                             # 摩托车;Motorcycle
    NON_MOTOR = 3,                              # 非机动车;Non-Motor
    BICYCLE = 4,                                # 自行车;Bicycle
    DUALTRIWHEELMOTORCYCLE = 5,                 # 两、三轮摩托车;DualTriWheelMotorcycle
    LIGHTMOTORCYCLE = 6,                        # 轻便摩托车;LightMotorcycle
    EMBASSYMOTORCYCLE = 7,                      # 使馆摩托车;EmbassyMotorcycle
    MARGINALMOTORCYCLE = 8,                     # 领馆摩托车;MarginalMotorcycle
    AREAOUTMOTORCYCLE = 9,                      # 境外摩托车;AreaoutMotorcycle
    FOREIGNMOTORCYCLE = 10,                     # 外籍摩托车;ForeignMotorcycle
    TRIALMOTORCYCLE = 11,                       # 试验摩托车;TrialMotorcycle
    COACHMOTORCYCLE = 12,                       # 教练摩托车;CoachMotorcycle
    PASSERBY = 13,                              # 行人;Passerby
    VANTRICYCLE = 14,                           # 厢式三轮车;VanTricycle
    MANNEDCONVERTIBLETRICYCLE = 15,             # 载人敞篷三轮车;MannedConvertibleTricycle
    NOMANNEDCONVERTIBLETRICYCLE = 16,           # 不载人敞篷三轮车;NoMannedConvertibleTricycle
    ELECTRICBIKE = 17,                          # "Electricbike" 二轮电瓶车;"Electricbike";
    FOURWHEELER = 18,                           # "FourWheelerNonMotor" 四轮非机动车;"FourWheelerNonMotor";

class EM_FEATURE_VERSION(IntEnum):
    """
    特征值版本类型;The type of feature version
    """
    UNKNOWN = 0,                                # 未知;Unknown
    FACE_LARGE_1_01_001 = 1,                    # 人脸，大模型，1.01.001;Face，large model，1.01.001
    FACE_LARGE_1_02_001 = 2,                    # 人脸，大模型，1.02.001;Face，large model，1.02.001
    FACE_LARGE_1_03_001 = 3,                    # 人脸，大模型，1.03.001;Face，large model，1.03.001
    FACE_LARGE_1_04_001 = 4,                    # 人脸，大模型，1.04.001;Face，large model，1.04.001
    FACE_MIDDLE_1_01_002 = 31,                  # 人脸，中模型，1.01.002;Face，middle model，1.01.002
    FACE_MIDDLE_1_02_002 = 32,                  # 人脸，中模型，1.02.002;Face，middle model，1.02.002
    FACE_MIDDLE_1_03_002 = 33,                  # 人脸，中模型，1.03.002;Face，middle model，1.03.002
    FACE_MIDDLE_1_04_002 = 34,                  # 人脸，中模型，1.04.002;Face，middle model，1.04.002
    FACE_MIDDLE_1_09_002 = 39,                  # 人脸，中模型，1.09.002;Face,middle model, 1.09.002;
    FACE_SMALL_1_01_003 = 61,                   # 人脸，小模型，1.01.003;Face，small model，1.01.003
    FACE_SMALL_1_02_003 = 62,                   # 人脸，小模型，1.02.003;Face，small model，1.02.003
    HUMAN_NONMOTOR = 91,                        # 人和非机动车，全局无版本号;Human and non-motor，no version
    HUMAN_NONMOTOR_FLOAT_1_00_01 = 92,          # 人和非机动车，全局浮点，1.00.01;Human and non-motor，global float，1.00.01
    HUMAN_NONMOTOR_HASH_1_00_01 = 93,           # 人和非机动车，全局哈希，1.00.01;Human and non-motor，global hash，1.00.01
    HUMAN_NONMOTOR_FLOAT_1_01_00 = 94,          # 人和非机动车，全局浮点，1.01.00;Human and non-motor，global float，1.01.00
    HUMAN_NONMOTOR_HASH_1_01_00 = 95,           # 人和非机动车，全局哈希，1.01.00;Human and non-motor, global hash, 1.01.01
    HUMAN_NONMOTOR_FLOAT_1_01_01 = 96,          # 人和非机动车，全局浮点，1.01.01;Human and non-motor, global float, 1.01.01;
    HUMAN_NONMOTOR_HASH_1_01_01 = 97,           # 人和非机动车，全局哈希，1.01.01;Human and non-motor, global hash, 1.01.01;
    HUMAN_NONMOTOR_FLOAT_1_01_03 = 98,          # 人和非机动车，全局浮点，1.01.03;Human and non-motor, global floa,1.01.03;
    HUMAN_NONMOTOR_HASH_1_01_03 = 99,           # 人和非机动车，全局哈希，1.01.03;Human and non-motor, global hash,1.01.03;
    TRAFFIC = 121,                              # 机动车，全局无版本号;Traffic，no version
    TRAFFIC_FLOAT = 122,                        # 机动车，全局浮点版本号0;Traffic，global float, 0
    TRAFFIC_FLOAT_1_00_01 = 123,                # 机动车，全局浮点版本号1.00.01;Traffic，global float, 1.00.01
    TRAFFIC_HASH_1_00_01 = 124,                 # 机动车，全局哈希版本号1.00.01;Traffic，global hash, 1.00.01
    TRAFFIC_FLOAT_1_00_02 = 125,                # 机动车，全局浮点版本号1.00.02;Traffic，global float, 1.00.02
    TRAFFIC_HASH_1_00_02 = 126,                 # 机动车，全局哈希版本号1.00.02;Traffic，global hash, 1.00.02
    SHANGTANG_FACE_1_5_0 = 151,                 # 商汤，人脸，1.5.0;ShangTang，face，1.5.0
    SHANGTANG_FACE_1_8_1 = 152,                 # 商汤，人脸，1.8.1;ShangTang，face，1.8.1
    SHANGTANG_FACE_2_1_3 = 153,                 # 商汤，人脸，2.1.3;ShangTang，face，2.1.3
    SHANGTANG_FACE_2_39_6 = 154,                # 商汤，人脸，2.39.6;ShangTang，face，2.39.6
    SHANGTANG_FACE_2_39_7 = 155,                # 商汤，人脸，2.39.7;ShangTang，face，2.39.7
    SHANGTANG_FACE_2_39_8 = 156,                # 商汤，人脸，2.39.8;ShangTang，face，2.39.8
    SHANGTANG_FACE_239 = 157,                   # 商汤，人脸，239;ShangTang，face，239
    SHANGTANG_FACE_242 = 158,                   # 商汤，人脸，242;ShangTang，face，242
    SHANGTANG_FACE_244 = 159,                   # 商汤，人脸，244;ShangTang，face，244
    SHANGTANG_FACE_245 = 160,                   # 商汤，人脸，245;ShangTang，face，245
    SHENMO_HUMAN_TRAFFIC_NON_2_4_2 = 181,       # 深瞐，人脸/机动车/非机动车，2.4.2;ShenMo,human/traffic/non-motor,2.4.2;
    SHENMO_HUMAN_TRAFFIC_NON_2_5_7 = 182,       # 深瞐，人脸/机动车/非机动车，2.5.7;ShenMo，human/traffic/non-motor，2.5.7

class EM_ALARM_TYPE(IntEnum):
    """
    报警业务类型;Alarm type
    """
    UNKNOWN = 0,                                # 未知类型;Unknown
    CROWD_DENSITY = 1,                          # 拥挤人群密度报警;Crowd density alarm
    NUMBER_EXCEED = 2,                          # 人数超限报警;the people number exceeds alarm
    CROWD_DENSITY_AND_NUMBER_EXCEED = 3,        # 拥挤人群密度报警和人数超限报警;Crowd density alarm and the number exceeds alarm

class NET_FLOWSTAT_DIRECTION(IntEnum):
    """
    车辆行驶方向;direction
    """
    UNKNOW = 0,                                 # 未知
    APPROACH = 1,                               # 上行, 即车辆离设备部署点越来越近;Uplink, the vehicle away from the device deployment point is getting closer
    LEAVE = 2,                                  # 下行, 即车辆离设备部署点越来越远;Go down, that the vehicle is farther away from  equipment deployment point

class NET_ROAD_DIRECTION(IntEnum):
    """
    道路方向;road direction
    """
    UNKNOW = 0,                                 # unknown
    TURNLEFT = 1,                               # left turn
    TURNRIGHT = 2,                              # right turn
    STRAIGHT = 3,                               # direction
    UTURU = 4,                                  # uturn
    NUM = 5,

class NET_TRAFFIC_JAM_STATUS(IntEnum):
    """
    道路拥挤状况;road jam status
    """
    UNKNOW = 0,                                 # 未知;unknown
    CLEAR = 1,                                  # 通畅;clear
    JAMMED = 2,                                 # 拥堵;jammed
    SLOWED = 3,                                 # 拥堵;slowed

class NET_TRAFFIC_ROAD_RANK(IntEnum):
    """
    道路等级;road rank
    """
    UNKNOWN = 0,                                # 未知;unknown
    RAPID = 1,                                  # 快速路;rapid
    TRUNK = 2,                                  # 主干路;trunk
    SUBTRUNK = 3,                               # 次干路;subtrunk
    BRANCH = 4,                                 # 支路;branch

class NET_EM_FLOW_ATTRIBUTE(IntEnum):
    """
    车道流量信息属性;Flow attribute
    """
    UNKNOWN = 0,                                # 未知;Unknown
    FLOW_DETECTION = 1,                         # 流量监测;Flow detection
    QUEUE_DETECTION = 2,                        # 排队检测;Queue detection

class EM_A_NET_EM_OVER_FLOW_STATE(IntEnum):
    """
    车辆排队长度溢出状态
    overflow state of car queue
    """
    EM_OVER_FLOW_STATE_UNKNOWN = 0,             # 状态未知;unknown;
    EM_OVER_FLOW_STATE_NOT_OVERFLOW = 1,        # 未溢出;not overflow;
    EM_OVER_FLOW_STATE_OVERFLOW = 2,            # 溢出;overflow;

class EM_RULE_TYPE(IntEnum):
    """
    规则类型;rule type
    """
    UNKNOWN = 0,                                # 未知;unknown
    NUMBER_STAT = 1,                            # 人数统计;number state
    MAN_NUM_DETECTION = 2,                      # 区域内人数统计;man number detection
    QUEUE_DETECTION = 3,                        # 排队检测;queue detection
    ANATOMYTEMP_DETECT = 4,                     # 人温度数据统计;anatomy temperature detection

class EM_OTHER_RULE_TYPE(IntEnum):
    """
    其他规则
    other rule
    """
    EM_OTHER_RULE_TYPE_UNKOWN = 0,              # 未知;Unknow;
    EM_OTHER_RULE_TYPE_AVERAGE_STAYTIME = 1,    # 平均滞留时间;Average Stay Time;

class EM_TRIGGER_TYPE(IntEnum):
    """
    触发类型;Trigger type
    """
    UNKNOWN = -1,                               # 未知类型;Unknown
    CAR_INSPECTION_DEV = 0,                     # 车检器;Car inspection device
    DADAR = 1,                                  # 雷达;Dadar
    VIDEO = 2,                                  # 视频;Video

class EM_VIOLATION_SNAP_SOURCE(IntEnum):
    """
    抓拍触发源;Snap trigger source
    """
    UNKNOWN = 0,                                # 未知类型;Unknown
    COIL = 1,                                   # 线圈;coil
    RADAR = 2,                                  # 雷达;Dadar
    VIDEO = 3,                                  # 视频;Video
    VIDEO_COIL = 4,                             # 视频和线圈混合;video and coil
    VIDEO_RADAR = 5,                            # 视频和雷达混合;video and radar
    VIDEO_COIL_RADAR = 6,                       # 视频、线圈和雷达混合;video and coil and radar
    FORCE_TRIGER = 7,                           # 强制触发;Force trigger
    PARKING_LOCK_STATUS = 8,                    # 车位锁状态;Parking lock status
    GATE_STATUS = 9,                            # 道闸状态;Gate status
    PERIPHERAL_STATUS = 10,                     # 外设状态;Peripheral status
    DRIVE_IN = 11,                              # 驶入;drive in
    DRIVE_OUT = 12,                             # 驶出;drive out

class EM_CAPTURE_PROCESS_END_TYPE(IntEnum):
    """
    抓拍过程结束类型;Capture process end type
    """
    UNKNOWN = -1,                               # 未知;Unknown
    ABNORMAL = 0,                               # 异常;Abnormal
    NORMAL = 1,                                 # 正常;Normal

class EM_ACCESS_CTL_IMAGE_TYPE(IntEnum):
    """
    图片类型；access control image type
    """
    UNKNOWN = -1,                               # 未知; Unknown
    LOCAL = 0,                                  # 本地人脸图库; Local face database
    SCENE = 1,                                  # 拍摄场景抠图; Cutout of scene picture
    FACE = 2,                                   # 人脸抠图; Cutout of face
    INFRARED = 3,                               # 红外抓图; Infrared capture
    COMPANION = 4,                              # 陪同人员抓图; Companion capture
    HEAT = 5,                                   # 热图;Heat capture;

class NET_ACCESSCTLCARD_SEX(IntEnum):
    """
    性别；sex
    """
    UNKNOWN = 0,                                # 未知; Unknown
    MALE = 1,                                   # 男; male
    FEMALE = 2,                                 # 女; female

class NET_ACCESS_CTL_EVENT_TYPE(IntEnum):
    """
    门禁事件类型；Entrance Guard Event Type
    """
    UNKNOWN = 0,                                # 未知; Unknown
    ENTRY = 1,                                  # 进门; Get In
    EXIT = 2,                                   # 出门; Get Out

class EM_A_NET_ACCESSCTLCARD_STATE(IntEnum):
    """
    卡状态
    Card Status
    """
    NET_ACCESSCTLCARD_STATE_UNKNOWN = -1,
    NET_ACCESSCTLCARD_STATE_NORMAL = 0,         # 正常;Normal;
    NET_ACCESSCTLCARD_STATE_LOSE = 1,           # 挂失;Lose;
    NET_ACCESSCTLCARD_STATE_LOGOFF = 2,         # 注销;Logoff;
    NET_ACCESSCTLCARD_STATE_FREEZE = 4,         # 冻结;Freeze;
    NET_ACCESSCTLCARD_STATE_ARREARAGE = 8,      # 欠费;Arrears;
    NET_ACCESSCTLCARD_STATE_OVERDUE = 16,       # 逾期;Overdue;
    NET_ACCESSCTLCARD_STATE_PREARREARAGE = 32,  # 预欠费(还是可以开门,但有语音提示);Pre-Arrears(still can open the door);

class NET_ACCESSCTLCARD_TYPE(IntEnum):
    """
    卡类型；Card Type
    """
    UNKNOWN = -1,
    GENERAL = 0,                                # 一般卡; General Card
    VIP = 1,
    GUEST = 2,                                  # 来宾卡; Guest Card
    PATROL = 3,                                 # 巡逻卡; Patrol Card
    BLACKLIST = 4,                              # 禁止名单卡; Blocklist Card
    CORCE = 5,                                  # 胁迫卡; Corce Card
    POLLING = 6,                                # 巡检卡; Polling Card
    GB_CUSTOM1 = 7,                             # 国标自定义1卡; card 1
    GB_CUSTOM2 = 8,                             # 国标自定义2卡; card 2
    TEMPORARY_PERSON = 9,                       # 临时人员; temporary person
    INVENTORY_PERSON = 10,                      # 清分人员; inventory person
    INVENTORY_DIRECTOR = 11,                    # 清分主管; inventory director
    SECURITY_GUARD = 12,                        # 保卫人员; security guard
    SECURITYGUARD_DIRECTOR = 13,                # 保卫主管; security guard director
    STORE_KEEPER = 14,                          # 库管员; store keeper
    STORE_DIRECTOR = 15,                        # 库主管; store director
    ESCORT_PERSON = 16,                         # 押运人员; escort person
    REPAIR_PERSON = 17,                         # 维修人员; repair person
    INSPECTOR = 18,                             # 检查人员; inspector
    SHENZHENLINK = 19,                          # 深圳通;ShenzhenTong
    MOTHERCARD = 0xff,                          # 母卡; Mother Card

class NET_ACCESS_DOOROPEN_METHOD(IntEnum):
    """
    开门方式(门禁事件,门禁出入记录,实际的开门方式)；Door Open Method(Entrance Guard Event,Entrance Guard get In/Out Record, Actual Open Door Method)
    """
    UNKNOWN = 0,
    PWD_ONLY = 1,                               # 密码开锁; Password
    CARD = 2,                                   # 刷卡开锁; Card
    CARD_FIRST = 3,                             # 先刷卡后密码开锁; First Card Then Password
    PWD_FIRST = 4,                              # 先密码后刷卡开锁; First Password Then Card
    REMOTE = 5,                                 # 远程开锁,如通过室内机或者平台对门口机开锁; Long-Range Open,Such as Through theIndoor Unit or Unlock the Door Machine Platform
    BUTTON = 6,                                 # 开锁按钮进行开锁; Open Door Button
    FINGERPRINT = 7,                            # 开锁; lock
    PWD_CARD_FINGERPRINT = 8,                   # 密码+刷卡+组合开锁; password+swipe card+ combination unlock
    PWD_FINGERPRINT = 10,                       # 密码+组合开锁; password+ combination unlock
    CARD_FINGERPRINT = 11,                      # 刷卡+组合开锁; swipe card+ combination unlock
    PERSONS = 12,                               # 多人开锁; multi-people unlock
    KEY = 13,                                   # 钥匙开门; Key
    COERCE_PWD = 14,                            # 胁迫密码开门; Use force password to open the door
    QRCODE = 15,                                # 二维码开门; Use QR Code
    FACE_RECOGNITION = 16,                      # 目标识别开门; face recogniton to open the door
    FACEIDCARD = 18,                            # 人证对比; comparsion of face and ID card
    FACEIDCARD_AND_IDCARD = 19,                 # 证件+人证比对; ID card and compasion of face and ID card
    BLUETOOTH = 20,                             # 蓝牙开门; Bluetooth
    CUSTOM_PASSWORD = 21,                       # 个性化密码开门; password
    USERID_AND_PWD = 22,                        # UserID+密码; UserID and password
    FACE_AND_PWD = 23,                          # 人脸+密码开锁; Face and password
    FINGERPRINT_AND_PWD = 24,                   # +密码开锁;  and password
    FINGERPRINT_AND_FACE = 25,                  # +人脸开锁;  and face
    CARD_AND_FACE = 26,                         # 刷卡+人脸开锁; Card and face
    FACE_OR_PWD = 27,                           # 人脸或密码开锁; Face or password
    FINGERPRINT_OR_PWD = 28,                    # 或密码开锁;  or password
    FINGERPRINT_OR_FACE = 29,                   # 或人脸开锁;  or face
    CARD_OR_FACE = 30,                          # 刷卡或人脸开锁; Card or face
    CARD_OR_FINGERPRINT = 31,                   # 刷卡或开锁; Card or
    FINGERPRINT_AND_FACE_AND_PWD = 32,          # +人脸+密码开锁;  and face and password
    CARD_AND_FACE_AND_PWD = 33,                 # 刷卡+人脸+密码开锁; Card and face and password
    CARD_AND_FINGERPRINT_AND_PWD = 34,          # 刷卡++密码开锁; Card and  and password
    CARD_AND_PWD_AND_FACE = 35,                 # 卡++人脸组合开锁; Card and password and face
    FINGERPRINT_OR_FACE_OR_PWD = 36,            # 或人脸或密码;  or face or password
    CARD_OR_FACE_OR_PWD = 37,                   # 卡或人脸或密码开锁; Card or face or password
    CARD_OR_FINGERPRINT_OR_FACE = 38,           # 卡或人脸开锁; Card  or face
    CARD_AND_FINGERPRINT_AND_FACE_AND_PWD = 39, # 卡++人脸+密码组合开锁; Card and  and face and password
    CARD_OR_FINGERPRINT_OR_FACE_OR_PWD = 40,    # 卡或人脸或密码开锁; Card or face or password
    FACEIPCARDANDIDCARD_OR_CARD_OR_FACE = 41,   # (证件+人证比对)或刷卡或人脸; ID card  and compasion of face and ID card or card or face
    FACEIDCARD_OR_CARD_OR_FACE = 42,            # 人证比对或刷卡(二维码)或人脸; ID card  and compasion of face or card or face
    DTMF = 43,                                  # DTMF开锁(包括SIPINFO,RFC2833,INBAND); DTMF unlock(include SIPINFO,RFC2833,INBAND)
    REMOTE_QRCODE = 44,                         # 远程二维码开门; remote QR code to open the door
    REMOTE_FACE = 45,                           # 远程人脸开门; remote face to open the door
    CITIZEN_FINGERPRINT = 46,                   # 人证比对开门(); Citizen picture()
    TEMPORARY_PASSWORD = 47,                    # 临时密码开门; Temporary password
    HEALTHCODE = 48,                            # 健康码开门; Health code
    IRIS = 49,                                  # 目标识别开锁;iris recognition unlock;
    IRIS_AND_PASSWORD = 50,                     # 目标+密码组合开锁;iris + password combination to unlock;
    FACE_AND_IRIS = 51,                         # 人脸+目标组合开锁;face + iris combination unlock;
    CARD_AND_IRIS = 52,                         # 卡+目标组合开锁;Card + iris combination unlock;
    IRIS_OR_PASSWORD = 53,                      # 目标或密码开锁;iris or password unlock;
    FACE_OR_IRIS = 54,                          # 人脸或目标开锁;face or iris unlock;
    CARD_OR_IRIS = 55,                          # 卡或目标开锁;Card or iris unlock;
    FACE_AND_IRIS_AND_PASSWORD = 56,            # 人脸+目标+密码组合开锁;face + iris + password combination to unlock;
    CARD_AND_FACE_AND_IRIS = 57,                # 卡+人脸+目标组合开锁;Card + face + iris combination unlock;
    CARD_AND_IRIS_AND_PASSWORD = 58,            # 卡+目标+密码组合开锁;Card + iris + password combination to unlock;
    FACE_OR_IRIS_OR_PASSWORD = 59,              # 人脸或目标或密码开锁;face or iris or password unlock;
    CARD_OR_FACE_OR_IRIS = 60,                  # 卡或人脸或目标开锁;Card or face or iris unlock;
    CARD_OR_IRIS_OR_PASSWORD = 61,              # 卡或目标或密码开锁;Card or iris or password unlock;
    CARD_AND_FACE_AND_IRIS_AND_PASSWORD = 62,   # 卡+人脸+目标+密码组合开锁;Card + face + iris + password combination to unlock;
    CARD_OR_FACE_OR_IRIS_OR_PASSWORD = 63,      # 卡或人脸或目标或密码开锁;Card or face or iris or password to unlock;

class NET_ATTENDANCESTATE(IntEnum):
    """
    考勤状态；attendance state
    """
    UNKNOWN = 0,                                # 未知; Unknown
    SIGNIN = 1,                                 # 签入; sign in
    GOOUT = 2,                                  # 外出; go out
    GOOUT_AND_RETRUN = 3,                       # 外出归来; go out and return
    SIGNOUT = 4,                                # 签出; sign out
    WORK_OVERTIME_SIGNIN = 5,                   # 加班签到; work overtime sign in
    WORK_OVERTIME_SIGNOUT = 6,                  # 加班签出; work overtime sign out

class EM_CARD_STATE(IntEnum):
    """
    当前门采集状态；Current collect status
    """
    UNKNOWN = -1,                               # 未知; Unknown
    SWIPE = 0,                                  # 门禁刷卡; Swipe
    COLLECTION = 1,                             # 门禁采集卡; Collection

class EM_HAT_STYLE(IntEnum):
    """
    帽子款式；hat style
    """
    UNKNOWN = 0,                                # 未知; unknown
    ORDINARY = 1,                               # 普通帽子; ordinary hat
    HELMET = 2,                                 # 头盔; helmet
    SAFETYHAT = 3,                              # 安全帽; safety hat
    EAVELESS = 4,                               # 无檐帽; eaveless hat
    PEAKEDCAP = 5,                              # 鸭舌帽; peakedcap
    FISHERMANHAT = 6,                           # 渔夫帽; fisher man hat
    NONE = 7,                                   # 未戴帽; no hat

class EM_UNIFIED_COLOR_TYPE(IntEnum):
    """
    统一后的颜色枚举；unified color type
    """
    TRANSPARENT = -1,                           # 透明; transparent
    UNKNOWN = 0,                                # 未知; unknown
    WHITE = 1,                                  # 白色; white
    ORANGE = 2,                                 # 橙色; orange
    PINK = 3,                                   # 粉色; pink
    BLACK = 4,                                  # 黑色; black
    RED = 5,                                    # 红色; red
    YELLOW = 6,                                 # 黄色; yellow
    GRAY = 7,                                   # 灰色; gray
    BLUE = 8,                                   # 蓝色; blue
    GREEN = 9,                                  # 绿色; green
    PURPLE = 10,                                # 紫色; purple
    BROWN = 11,                                 # 棕色; brown

class EM_LIFT_CALLER_TYPE(IntEnum):
    """
    梯控方式触发者；lift caller type
    """
    UNKNOWN = 0,                                # 未知; unknown
    VTO = 1,                                    # VTO 呼叫; VTO call
    PLATFORM = 2,                               # 平台呼叫; platform call
    LOCAL_AUTH = 3,                             # 本机鉴权呼叫; local auth call
    ACCESS_CONTROL = 4,                         # 门禁呼梯;Access control call elevator;

class EM_PASSERBY_DB_DUPLICATE_REMOVE_TYPE(IntEnum):
    """
    路人库去重策略类型；Passerby DB duplicate remove strategy
    """
    UNKNOWN = -1,                               # 未知; unknown
    ALL = 0,                                    # 无条件去重; Unconditional de duplication
    TIME = 1,                                   # 按时间间隔去重; De duplication by time interval
    TIME_SLOT = 2,                              # 按时间段间隔去重; De duplication at intervals

class EM_PASSERBY_DB_OVERWRITE_TYPE(IntEnum):
    """
    路人库满时覆盖策略；Coverage policy when the passer-by database is full
    """
    UNKNOWN = -1,                               # 未知; unknown
    FULL_STOP = 0,                              # 满停止; Full stop
    FULL_COVERAGE = 1,                          # 满覆盖; Full coverage

class EM_FACE_DB_TYPE(IntEnum):
    """
    人脸数据类型；face data type
    """
    UNKOWN = 0,                                 # 未知; unknown
    HISTORY = 1,                                # 历史数据库,存放的是检测出的人脸信息,一般没有包含人脸对应人员信息; History database, storage is to detect the human face information, usually does not contain face corresponding personnel information
    BLACKLIST = 2,                              # 阻止名单数据库(现在用作注册库); The blocklist database (it is registe DB now)
    WHITELIST = 3,                              # 允许名单数据库,废弃; The allowlist database (unuse)
    ALARM = 4,                                  # 报警库, 废弃; Alarm library (unuse)
    PASSERBY = 5,                               # 路人库; Passerby DB

class EM_USER_TYPE(IntEnum):
    """
    用户类型；user type
    """
    UNKNOWN = -1,                               # 未知; unknown
    ORDINARY = 0,                               # 普通用户; ordinary user
    BLACKLIST = 1,                              # 禁止名单用户; blocklist user
    VIP = 2,
    GUEST = 3,                                  # 来宾用户; guest user
    PATROL = 4,                                 # 巡逻用户; patrol user
    DISABLED = 5,                               # 残障用户; unable user
    FROZEN = 6,                                 # 冻结用户; frozen user
    LOGOUT = 7,                                 # 注销用户; logout user
    LOSSCARD = 8,                               # 挂失卡; loss card

class EM_OPERATE_FACERECONGNITION_GROUP_TYPE(IntEnum):
    """
    人员组操作枚举；staff group operation enumeration
    """
    UNKOWN = 0,                                 # 未知; unknown
    ADD = 1,                                    # 添加人员组信息; add staff group info
    MODIFY = 2,                                 # 修改人员组信息; modify staff group info
    DELETE = 3,                                 # 删除人员组信息; delete staff group info

class EM_FACE_COMPARE_MODE(IntEnum):
    """
    人脸对比模式；Face contrast pattern
    """
    UNKOWN = 0,                                 # 未知; unknown
    NORMAL = 1,                                 # 正常; normal
    AREA = 2,                                   # 指定人脸区域组合区域; Specify the face region combination area
    AUTO = 3,                                   # 智能模式,算法根据人脸各个区域情况自动选取组合; Intelligent model, the algorithm according to the situation of facial regions automatically select combination

class EM_FACE_AREA_TYPE(IntEnum):
    """
    人脸区域；Face region
    """
    UNKOWN = 0,                                 # 未知; Unknown
    EYEBROW = 1,                                # 眉毛; eyebrow
    EYE = 2,                                    # 眼睛; eye
    NOSE = 3,                                   # 鼻子; nose
    MOUTH = 4,                                  # 嘴巴; mouth
    CHEEK = 5,                                  # 脸颊; face

class EM_FINDPIC_QUERY_MODE(IntEnum):
    """
    以图搜图查询模式；The query mode of searching face database by picture
    """
    UNKOWN = 0,                                 # 未知; Unknown
    PASSIVE = 1,                                # 被动查询; Passive
    ACTIVE = 2,                                 # 主动推送; Active

class EM_FINDPIC_QUERY_ORDERED(IntEnum):
    """
    以图搜图结果上报排序方式；The sort order of the result about searching face database by picture
    """
    SIMILARITY = 0,                             # 按相似度从高到底; From high to low by similarity
    FORWARD = 1,                                # 按时间正序; Forward by time
    REVERSE = 2,                                # 按时间倒序; Reverse by time

class EM_FACERECOGNITION_FACE_TYPE(IntEnum):
    """
    目标识别人脸类型；target recognition face type
    """
    UNKOWN = 0,                                 # 未知; Unknown
    ALL = 1,                                    # 所有人脸;  All the faces
    REC_SUCCESS = 2,                            # 识别成功; recognition success
    FAIL = 3,                                   # 识别失败; recognition fail

class EM_DEV_EVENT_FACEDETECT_FEATURE_TYPE(IntEnum):
    """
    人脸检测对应人脸特征类型；feature type of detected human face
    """
    UNKNOWN = 0,                                # 未知; unknown
    WEAR_GLASSES = 1,                           # 戴眼镜; wearing glasses
    SMILE = 2,                                  # 微笑; smile
    ANGER = 3,                                  # 愤怒; anger
    SADNESS = 4,                                # 悲伤; sadness
    DISGUST = 5,                                # 厌恶; disgust
    FEAR = 6,                                   # 害怕; fear
    SURPRISE = 7,                               # 惊讶; surprise
    NEUTRAL = 8,                                # 正常; neutral
    LAUGH = 9,                                  # 大笑; laugh
    NOGLASSES = 10,                             # 没戴眼镜; not wear glasses
    HAPPY = 11,                                 # 高兴; happy
    CONFUSED = 12,                              # 困惑; confused
    SCREAM = 13,                                # 尖叫; scream
    WEAR_SUNGLASSES = 14,                       # 戴太阳眼镜; wearing sun glasses

class EM_GLASS_STATE_TYPE(IntEnum):
    """
    戴眼镜状态
    Wearing glasses state
    """
    EM_GLASS_STATE_TYPE_UNKNOWN = 0,            # 未知;Unknown;
    EM_GLASS_STATE_TYPE_NOT_WEARING = 1,        # 未戴;Not wearing;
    EM_GLASS_STATE_TYPE_CONVENTIONAL_GLASSES = 2,    # 戴常规眼镜;Wear regular glasses;
    EM_GLASS_STATE_TYPE_SUN_GLASSES = 3,        # 戴太阳眼镜;Wear sunglasses;
    EM_GLASS_STATE_TYPE_BLACK_GLASSES = 4,      # 戴黑框眼镜;Wear black framed glasses;

class EM_OPERATE_FACERECONGNITIONDB_TYPE(IntEnum):
    """
    目标识别数据库操作；target recognition database operations
    """
    UNKNOWN = 0,                                # 未知; unknown
    ADD = 1,                                    # 添加人员信息和人脸样本,如果人员已经存在,图片数据和原来的数据合并; Add personnel information and face samples, if researchers already exists, image data and the original data
    DELETE = 2,                                 # 删除人员信息和人脸样本;  Delete the personnel information and face samples
    FACERECONGNITIONDB_MODIFY = 3,              # 修改人员信息和目标样本,人员的UID标识必填;Modify person info and human target sample, must input person UID
    FACERECONGNITIONDB_DELETE_BY_UID = 4,       # 通过UID删除人员信息和目标样本;Delete person info and human target via UID
    FACERECONGNITIONDB_DELETE_BY_UUID = 5,      # 通过UUID删除人员信息和目标样本;Delete personnel information and target samples through UUID

class EM_ERRORCODE_TYPE(IntEnum):
    """
    错误代码，emOperateType操作类型为EM_OPERATE_FACERECONGNITIONDB_TYPE.DELETE_BY_UID时使用；error code, it is effective when emOperateType is EM_OPERATE_FACERECONGNITIONDB_TYPE.DELETE_BY_UID
    """
    UNKNOWN = -1,                               # 未知错误; unknown
    SUCCESS = 0,                                # 成功; success
    PERSON_NOT_EXIST = 1,                       # 人员不存在;  person not exist
    DATABASE_ERROR = 2,                         # 数据库操作失败;  database error

class EM_CERTIFICATE_TYPE(IntEnum):
    """
    证件类型; ID type
    """
    UNKNOWN = 0,                                # 未知错误; unknown
    IC = 1,                                     # 证件; ID
    PASSPORT = 2,                               # 护照;  passport
    OUTERGUARD = 3,

class EM_REAL_DATA_TYPE(IntEnum):
    """
    实时预览回调数据类型; stream date type
    """
    PRIVATE = 0,                                # 私有码流; private stream
    GBPS = 1,                                   # 国标PS码流，支持音频转码为G711A; Chinese standard ps stream
    TS = 2,                                     # TS码流，支持音频转码为AAC，MP2;  TS stream
    MP4 = 3,                                    # MP4文件(从回调函数出来的是私有码流数据,参数dwDataType值为0)，支持音频转码为MP2，AAC， G711A;  MP4 file(the callback function supply the private stream data, the parama dwDataType is 0 )
    H264 = 4,                                   # 裸视频流,h264与h265都能转码成功;  raw video stream,both h264 and h265 can convert successfully
    FLV_STREAM = 5,                             # 流式FLV，支持音频转码为AAC，G711A，G711U;  FLV stream
    PS = 6,                                     # PS码流，支持音频转码为AAC，MP2;  PS stream
    DHTS = 7,                                   # DHTS;  DHTS
    CDJFPS = 8,                                 # PS-原始音频格式是G711A和G711U、MP2的，音频不转码，其他的，音频转码成AAC;   PS(if Audio format is G711A,G711U or MP2 will not transcoding,else convert to AAC)

class EM_AUDIO_DATA_TYPE(IntEnum):
    """
    音频数据类型; audio data type
    """
    DEFAULT = 0,                                # 默认; default
    AAC = 1,                                    # 音频强制转换为AAC; AAC
    G711A = 2,                                  # 音频强制转换为G711A;  G711A
    G711U = 3,                                  # 音频强制转换为G711U;  G711U
    MP2 = 4,                                    # 音频强制转换为MP2;  MP2

class EM_TITLE_TEXT_ALIGN(IntEnum):
    """
    通道标题对齐信息; Channel title alignment info
    """
    EM_TEXT_ALIGN_INVALID = 0,                  # 无效的对齐方式; Invalid alignment mathod;
    EM_TEXT_ALIGN_LEFT = 1,                     # 左对齐; Left alignment;
    EM_TEXT_ALIGN_XCENTER = 2,                  # X坐标中对齐; X coordinate alignment;
    EM_TEXT_ALIGN_YCENTER = 3,                  # Y坐标中对齐; Y coordinate alignment;
    EM_TEXT_ALIGN_CENTER = 4,                   # 居中; Center;
    EM_TEXT_ALIGN_RIGHT = 5,                    # 右对齐; Right alignment;
    EM_TEXT_ALIGN_TOP = 6,                      # 按照顶部对齐; By top alignment;
    EM_TEXT_ALIGN_BOTTOM = 7,                   # 按照底部对齐; By bottom alignment;
    EM_TEXT_ALIGN_LEFTTOP = 8,                  # 按照左上角对齐; By upper left alignment;
    EM_TEXT_ALIGN_CHANGELINE = 9,               # 换行对齐; Next row alignment;

class EM_FONT_SOLUTION(IntEnum):
    """
     OSD中的字体方案FontSolution;OSD font solution
    """
    EM_FONT_UNKNOWN = 0,                        # 未知; Unknown;
    EM_FONT_DFAULT = 1,                         # 默认字体 "default-font"; default-font;
    EM_FONT_SIMKAI = 2,                         # 楷体 "simkai"; simkai;
    EM_FONT_SIMSUN = 3,                         # 宋体"simsun"; simsun;

class EM_CURRENT_STATE_TYPE(IntEnum):
    """
     电源电流状态类型;power current status type
    """
    EM_CURRENT_STATE_UNKNOWN = 0,
    EM_CURRENT_STATE_OVER_CURRENT = 1,          # 电流过载; current too high;
    EM_CURRENT_STATE_NORMAL = 2,                # 电流正常; current normal;
    EM_CURRENT_STATE_UNDER_CURRENT = 3,         # 电源欠流; current too low;

class EM_VOLTAGE_STATE_TYPE(IntEnum):
    """
     电源电压状态类型;power voltage status type
    """
    EM_VOLTAGE_STATE_UNKNOWN = 0,               # 未知; unknown;
    EM_VOLTAGE_STATE_OVER = 1,                  # 过压; over;
    EM_VOLTAGE_STATE_NORMAL = 2,                # 正常; normal;
    EM_VOLTAGE_STATE_UNDER = 3,                 # 欠压; under;

class EM_BATTERY_EXIST_STATE(IntEnum):
    """
     电池在位状态;battery in-place status
    """
    EM_BATTERY_EXIST_STATE_UNKNOWN = 0,
    EM_BATTERY_EXIST_STATE_EXIST = 1,           # 电池在位; battery in-place;
    EM_BATTERY_EXIST_STATE_MISSING = 2,         # 电池丢失; battery lost;

class EM_BATTERY_STATE(IntEnum):
    """
     电池电量状态;battery status
    """
    EM_BATTERY_STATE_UNKNOWN = 0,
    EM_BATTERY_STATE_NORMAL = 1,                # 电量正常; normal power;
    EM_BATTERY_STATE_LOW = 2,                   # 电量低; low power;

class NET_EM_CONFIG_TYPE(IntEnum):
    """
     每个通道对应的配置类型;config type
    """
    DAYTIME = 0,                                # 白天; day time;
    NIGHT = 1,                                  # 夜晚; night;
    NORMAL = 2,                                 # 普通; normal;

class NET_EM_EXPOSURE_MODE(IntEnum):
    """
     曝光模式;exposure mode
    """
    AUTO = 0,                                   # 默认自动; auto;
    LOWNICE = 1,                                # 低噪声; low nice;
    ANTISHADOW = 2,                             # 防拖影; anti shadow;
    MANUALRANGE = 4,                            # 手动区间; manual range;
    APERTUREFIRST = 5,                          # 光圈优先; aperture first;
    MANUALFIXATION = 6,                         # 手动固定; manual fixation;
    GIANFIRST = 7,                              # 增益优先; gian first;
    SHUTTERFIRST = 8,                           # 快门优先; shutter first;
    FLASHMATCH = 9,                             # 闪光灯匹配模式; flash match;

class EM_DOUBLE_EXPOSURE_TYPE(IntEnum):
    """
     双快门的支持类型;Support Type of Double Shutter
    """
    UNKNOWN = -1,                               # 未知; Unknown;
    NOT_SUPPORT = 0,                            # 不支持; Not support;
    SUPPORT_FULL_FRAM = 1,                      # 支持双快门全帧率，即图像和视频只有快门参数不同; Support double shutter full frame rate, i.e. image and video only have different shutter parameters;
    SUPPORT_HALF_FRAM = 2,                      # 支持双快门半帧率，即图像和视频快门及白平衡参数均不同; Support double shutter full frame rate, i.e. images and videos have only different shutter parameters;
    ALL = 3,                                    # 支持双快门全帧率和半帧率; Supporting full frame rate and half frame rate with double shutters;

class SDK_PTZ_ControlType(IntEnum):
    """
    通用云台控制命令; General PTZ control command
    """
    UP_CONTROL = 0,                             # 上 速度对应parma2(1-8);Up;
    DOWN_CONTROL = 1,                           # 下 速度对应parma2(1-8);Down;
    LEFT_CONTROL = 2,                           # 左 速度对应parma2(1-8);Left;
    RIGHT_CONTROL = 3,                          # 右 速度对应parma2(1-8);Right;
    ZOOM_ADD_CONTROL = 4,                       # 变倍+ 对应param2;+ Zoom in;
    ZOOM_DEC_CONTROL = 5,                       # 变倍- 对应param2;- Zoom out;
    FOCUS_ADD_CONTROL = 6,                      # 调焦- 对应param2;- Zoom in;
    FOCUS_DEC_CONTROL = 7,                      # 调焦+ 对应param2;+ Zoom out;
    APERTURE_ADD_CONTROL = 8,                   # 光圈+ 对应param2;+ Aperture;
    APERTURE_DEC_CONTROL = 9,                   # 光圈- 对应param2;- Aperture;
    POINT_MOVE_CONTROL = 10,                    # 转至预置点 param2为预置点序号;Go to preset;
    POINT_SET_CONTROL = 11,                     # 设置 param2为预置点序号，最大序号可以从云台能力集中获取 param4可以传预置点名称，预置点名称最大有效值为63字节。;Set;
    POINT_DEL_CONTROL = 12,                     # 删除 param2为预置点序号;Delete;
    POINT_LOOP_CONTROL = 13,                    # 点间巡航 param1为巡航线路;Tour;
    LAMP_CONTROL = 14,                          # 灯光雨刷 对应param1(1-开启,0-关闭);Light and wiper;
    LEFTTOP = 32,                               # 左上; Upper left;
    RIGHTTOP = 33,                              # 右上; Upper right;
    LEFTDOWN = 34,                              # 左下; Down left;
    RIGHTDOWN = 35,                             # 右下; Down right;
    ADDTOLOOP = 36,                             # 加入预置点到巡航 巡航线路 预置点值; Add preset to tour tour preset value;
    DELFROMLOOP = 37,                           # 删除巡航中预置点 巡航线路 预置点值; Delete preset in tour tour preset value;
    CLOSELOOP = 38,                             # 清除巡航 巡航线路; Delete tour tour;
    STARTPANCRUISE = 39,                        # 开始水平旋转; Begin pan rotation;
    STOPPANCRUISE = 40,                         # 停止水平旋转; Stop pan rotation;
    SETLEFTBORDER = 41,                         # 设置左边界; Set left limit;
    SETRIGHTBORDER = 42,                        # 设置右边界; Set right limit;
    STARTLINESCAN = 43,                         # 开始线扫; Begin scanning;
    CLOSELINESCAN = 44,                         # 停止线扫; Stop scanning;
    SETMODESTART = 45,                          # 设置模式开始 模式线路; Start mode mode line;
    SETMODESTOP = 46,                           # 设置模式结束 模式线路; Stop mode mode line;
    RUNMODE = 47,                               # 运行模式 模式线路; Enable mode Mode line;
    STOPMODE = 48,                              # 停止模式 模式线路; unable mode Mode line;
    DELETEMODE = 49,                            # 清除模式 模式线路; Delete mode Mode line;
    REVERSECOMM = 50,                           # 翻转命令; Flip;
    FASTGOTO = 51,                              # 快速定位 水平坐标(-8191~8191) 垂直坐标(-8191~8191) 变倍(-16~16); 3D position X address(-8191~8191) Y address(-8191~8191) zoom(-16~16);
    AUXIOPEN = 52,                              # 辅助开关开 辅助点(param4对应 PTZ_CONTROL_AUXILIARY,param1、param2、param3无效,dwStop设置为FALSE); auxiliary open Auxiliary point;
    AUXICLOSE = 53,                             # 辅助开关关 辅助点(param4对应 PTZ_CONTROL_AUXILIARY,param1、param2、param3无效,dwStop设置为FALSE); Auxiliary close Auxiliary point;
    OPENMENU = 54,                              # 打开球机菜单; Open dome menu;
    CLOSEMENU = 55,                             # 关闭菜单; Close menu;
    MENUOK = 56,                                # 菜单确定; Confirm menu;
    MENUCANCEL = 57,                            # 菜单取消; Cancel menu;
    MENUUP = 58,                                # 菜单上; menu up;
    MENUDOWN = 59,                              # 菜单下; menu down;
    MENULEFT = 60,                              # 菜单左; menu left;
    MENURIGHT = 61,                             # 菜单右; Menu right;
    ALARMHANDLE = 64,                           # 报警联动云台 parm1：报警输入通道；parm2：报警联动类型1-预置点2-线扫3-巡航；parm3：联动值,如预置点号; Alarm activate PTZ param1:Alarm input channel; param2:Alarm activation type 1-preset 2-scan 3-tour; param 3:activation value,such as preset value.;
    MATRIXSWITCH = 65,                          # 矩阵切换 parm1：预览器号(视频输出号)；parm2：视频输入号；parm3：矩阵号; Matrix switch param1:monitor number(video output number);param2:video input number;param3:matrix number;
    LIGHTCONTROL = 66,                          # 灯光控制器; Light controller;
    EXACTGOTO = 67,                             # 三维精确定位 parm1：水平角度(0~3600)；parm2：垂直坐标(-1800-1800)；parm3：变倍(1~128),变倍为档位,并非实际变倍倍数; 3D accurately positioning param1:Pan degree(0~3600); param2: tilt coordinates(-1800-1800); param3:zoom(1~128);
    RESETZERO = 68,                             # 三维定位重设零位; Reset 3D positioning as zero;
    MOVE_ABSOLUTELY = 69,                       # 绝对移动控制命令,param4对应结构 PTZ_CONTROL_ABSOLUTELY; Absolute motion control commands, param4 corresponding struct PTZ_CONTROL_ABSOLUTELY;
    MOVE_CONTINUOUSLY = 70,                     # 持续移动控制命令,param4对应结构 PTZ_CONTROL_CONTINUOUSLY; Continuous motion control commands, param4 corresponding struct PTZ_CONTROL_CONTINUOUSLY;
    GOTOPRESET = 71,                            # 云台控制命令,以一定速度转到预置位点,parm4对应结构PTZ_CONTROL_GOTOPRESET; PTZ control command, at a certain speed to preset locus, param4 corresponding struct PTZ_CONTROL_GOTOPRESET;
    SET_VIEW_RANGE = 73,                        # 设置可视域(param4对应结构 PTZ_VIEW_RANGE_INFO); Set to horizon(param4 corresponding struct PTZ_VIEW_RANGE_INFO);
    FOCUS_ABSOLUTELY = 74,                      # 绝对聚焦(param4对应结构PTZ_FOCUS_ABSOLUTELY); Absolute focus(param4 corresponding struct PTZ_FOCUS_ABSOLUTELY);
    HORSECTORSCAN = 75,                         # 水平扇扫(param4对应PTZ_CONTROL_SECTORSCAN,param1、param2、param3无效); Level fan sweep(param4 corresponding PTZ_CONTROL_SECTORSCAN,param1,param2,param3 is invalid);
    VERSECTORSCAN = 76,                         # 垂直扇扫(param4对应PTZ_CONTROL_SECTORSCAN,param1、param2、param3无效); Vertical sweep fan(param4correspondingPTZ_CONTROL_SECTORSCAN,param1,param2,param3 is invalid);
    SET_ABS_ZOOMFOCUS = 77,                     # 设定绝对焦距、聚焦值,param1为焦距,范围:[0,255],param2为聚焦,范围:[0,255],param3、param4无效; Set absolute focus, focus on value, param1 for focal length, range: [0-255], param2 as the focus, scope: [0-255], param3, param4 is invalid;
    SET_FISHEYE_EPTZ = 78,                      # 控制鱼眼电子云台,param4对应结构 PTZ_CONTROL_SET_FISHEYE_EPTZ; Control fish eye PTZ, param4corresponding to structure PTZ_CONTROL_SET_FISHEYE_EPTZ;
    SET_TRACK_START = 79,                       # 轨道机开始控制(param4对应结构体为 PTZ_CONTROL_SET_TRACK_CONTROL,dwStop传FALSE, param1、param2、param3无效); Track start control(param4 corresponding to structure PTZ_CONTROL_SET_TRACK_CONTROL,dwStop set as FALSE, param1, param2, param3 is invalid);
    SET_TRACK_STOP = 80,                        # 轨道机停止控制(param4对应结构体为 PTZ_CONTROL_SET_TRACK_CONTROL,dwStop传FALSE,param1、param2、param3无效); Track stop control (param4 corresponding to structure PTZ_CONTROL_SET_TRACK_CONTROL,dwStop set as FALSE, param1, param2, param3 is invalid);
    RESTART = 81,                               # 云台重启命令(param1、param2、param3 param4 均无效,dwStop设置为FALSE); To restart the PTZ(param1,param2,param3,param4 are all invalid ,dwStop set to FALSE );
    INTELLI_TRACKMOVE = 82,                     # 云台连续移动,枪球联动专用,param4对应结构 PTZ_CONTROL_INTELLI_TRACKMOVE; Continuous motion control commands,track move,param4 corresponding struct PTZ_CONTROL_INTELLI_TRACKMOVE;
    SET_FOCUS_REGION = 83,                      # 设置区域聚焦参数(param4对应结构体为PTZ_CONTROL_SET_FOCUS_REGION,dwStop传FALSE,param1、param2、param3无效); set the focus region(param4 corresponding to PTZ_CONTROL_SET_FOCUS_REGION,dwStop set to FALSE,param1,param2,param3 are all invalid);
    PAUSELINESCAN = 84,                         # 暂停线扫(param1、param2、param3param4均无效，dwStop设置为FALSE); Pause Scan(param1,param2,param3,param4 are all invalid ,dwStop set to FALSE);
    INTELLI_SETLENSWISDOMSTATE = 85,            # 目标跟踪时设置聚焦模式(param4对应结构体为PTZ_CONTROL_INTELLI_SETLENSWISDOMSTATE,dwStop传FALSE,param1、param2、param3无效); Set focus mode when tracking target(param4 corresponding to PTZ_CONTROL_INTELLI_SETLENSWISDOMSTATE, dwStop set to FALSE,param1,param2,param3 are all invalid);
    INTELLI_SETFOCUSAREA = 86,                  # 设置聚焦区域(param4对应结构体为PTZ_CONTROL_INTELLI_SETFOCUSAREA,dwStop传FALSE,param1、param2、param3无效),注：目标跟踪若不需设置聚焦区域，因聚焦区域会沿袭上次主动设置状态，故需主动调用此接口取消设置聚焦区域; Set focus area when tracking target(param4 corresponding to PTZ_CONTROL_INTELLI_SETFOCUSAREA, dwStop set to FALSE,param1,param2,param3 are all invalid),Note: if target tracking do not need set focus area,user need to set cancel by this interface;
    UP_TELE = 112,                              # 上 + TELE param1=速度(1-8),下同; Up + TELE param1=speed (1-8);
    DOWN_TELE = 113,                            # 下 + TELE; Down + TELE;
    LEFT_TELE = 114,                            # 左 + TELE; Left + TELE;
    RIGHT_TELE = 115,                           # 右 + TELE; Right + TELE;
    LEFTUP_TELE = 116,                          # 左上 + TELE; Upper left + TELE;
    LEFTDOWN_TELE = 117,                        # 左下 + TELE; Down left + TELE;
    TIGHTUP_TELE = 118,                         # 右上 + TELE; Upper right + TELE;
    RIGHTDOWN_TELE = 119,                       # 右下 + TELE; Down right + TELE;
    UP_WIDE = 120,                              # 上 + WIDE param1=速度(1-8),下同; Up + WIDE param1=speed (1-8);
    DOWN_WIDE = 121,                            # 下 + WIDE; Down + WIDE;
    LEFT_WIDE = 122,                            # 左 + WIDE; Left + WIDE;
    RIGHT_WIDE = 123,                           # 右 + WIDE; Right + WIDE;
    LEFTUP_WIDE = 124,                          # 左上 + WIDE; Upper left + WIDE;
    LEFTDOWN_WIDE = 125,                        # 左下 + WIDE; Down left+ WIDE;
    TIGHTUP_WIDE = 126,                         # 右上 + WIDE; Upper right + WIDE;
    RIGHTDOWN_WIDE = 127,                       # 右下 + WIDE; Down right + WIDE;
    GOTOPRESETSNAP = 128,                       # 转至预置点并抓图; goto preset and snap;
    DIRECTIONCALIBRATION = 130,                 # 校准云台方向（双方向校准）; calibtate direction（two direction）;
    SINGLEDIRECTIONCALIBRATION = 131,           # 校准云台方向（单防线校准）,param4对应结构 NET_IN_CALIBRATE_SINGLEDIRECTION; calibtate direction（single direction）,param4 corresponding to structure NET_IN_CALIBRATE_SINGLEDIRECTION;
    MOVE_RELATIVELY = 132,                      # 云台相对定位,param4对应结构 NET_IN_MOVERELATIVELY_INFO; move Relatively, param4 corresponding to structure NET_IN_MOVERELATIVELY_INFO;
    SET_DIRECTION = 133,                        # 设置云台方向, param4对应结构 NET_IN_SET_DIRECTION_INFO; set PTZ Direction, param4 corresponding to NET_IN_SET_DIRECTION_INFO;
    BASE_MOVE_ABSOLUTELY = 134,                 # 精准绝对移动控制命令,param4对应结构 NET_IN_PTZBASE_MOVEABSOLUTELY_INFO（通过 CFG_CAP_CMD_PTZ 命令获取云台能力集( CFG_PTZ_PROTOCOL_CAPS_INFO )，若bSupportReal为TRUE则设备支持该操作）; Absolute motion control commands,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_INFO;
    BASE_MOVE_CONTINUOUSLY = 135,               # 云台连续移动控制命令, param4对应结构NET_IN_PTZBASE_MOVE_CONTINUOUSLY_INFO.  通过CFG_CAP_CMD_PTZ命令获取云台能力集
                                                # 若CFG_PTZ_PROTOCOL_CAPS_INFO中stuMoveContinuously字段的 stuType.bSupportExtra为TRUE, 表示设备支持该操作;PTZ continuous movement control command,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_INFO;
    BASE_SET_FOCUS_MAP_VALUE = 136,             # 设置当前位置聚焦值, param4对应结构体NET_IN_PTZBASE_SET_FOCUS_MAP_VALUE_INFO;Set the current position focus value,param4 corresponding to NET_IN_PTZBASE_SET_FOCUS_MAP_VALUE_INFO;
    BASE_MOVE_ABSOLUTELY_ONLYPT = 137,          # 绝对定位独立控制PT并能以度/秒为单位的速度控制, param4对应结构NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYPT_INFO;Absolute positioning independent control Pt and speed control in degrees per second,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYPT_INFO;
    BASE_MOVE_ABSOLUTELY_ONLYZOOM = 138,        # 绝对定位独立控制zoom，并能控制变倍速度, param4对应结构NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYZOOM_INFO;Absolute positioning independent control zoom,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYZOOM_INFO;
    STOP_MOVE = 139,                            # 云台移动停止,同时也停止巡航模式,param4对应结构体 NET_IN_STOP_MOVE_INFO;The movement of the gimbal stops, and the cruise mode is also stopped at the same time, param4 corresponds to the structure NET_IN_STOP_MOVE_INFO;
    TOTAL = 140,                                # 最大命令值; max command value;

class EM_GET_DISTANCE_RES_STATUS(IntEnum):
    """
    获取激光测距仪距离返回的数据类型; get laser rangefinder distance return value state type
    """
    UNKNOWN = -1,                               # 未知; Unknown;
    SUCCESS = 0,                                # 成功; Success;
    BEYOND_PITCH_LIMIT = 1,                     # 超出俯仰角限制; Beyond pitch limit;
    INTERFACE_EXCEPTION = 2,                    # 接口异常; Interface exception;
    GENERAL_ERROR = 3,                          # 通用错误; General Error;
    LASER_NO_DATA_RETURN = 4,                   # 激光测距仪无数据返回。; Laser Range Finder No Data Return;
    LASER_DATA_LENGTH_ERROR = 5,                # 激光测距仪返回的数据长度错误; Data Length Error Returned by Laser Range Finder;
    LASER_DATA_FORMAT_ERROR = 6,                # 激光测距仪返回的数据格式不正确; The data format returned by laser rangefinder is incorrect;
    LASER_DATA_VERIFIED_ERROR = 7,              # 激光测距仪返回的数据校验失败; Failure to verify data returned by laser rangefinder;

class EM_CFG_LIGHTING_MODE(IntEnum):
    """
    灯光模式; The light pattern
    """
    UNKNOWN = 0,                                # 未知; Unknown;
    MANUAL = 1,                                 # 手动; Manual;
    ZOOMPRIO = 2,                               # 倍率优先; Zoom ratio is preferred;
    TIMING = 3,                                 # 定时模式; Timing;
    AUTO = 4,                                   # 自动; Auto;
    OFF = 5,                                    # 关闭模式; Off;

class EM_SDK_PTZ_PRESET_STATUS(IntEnum):
    """
    预置点状态枚举; PTZ preset status type
    """
    UNKNOWN = 0,                                # 未知; unknown;
    REACH = 1,                                  # 预置点到达; preset reach the point;
    UNREACH = 2,                                # 预置点未到达; preset do not reach the point yet;

class EM_SDK_PTZ_PAN_TILT_STATUS(IntEnum):
    """
    预置点状态枚举; P/T movement status of gimbal
    """
    UNKNOWN = 0,                                # 未知; unknown;
    IDLE = 1,                                   # 空闲状态; Idle state
    MOVING = 2,                                 # 运动状态; Movement status

class NET_EM_MASK_TYPE(IntEnum):
    """
    遮挡块形状类型; block shape type
    """
    UNKNOWN = 0,                                # 未知; unknown;
    RECT = 1,                                   # 矩形; rectangle;
    POLYGON = 2,                                # 多边形; edge shape;

class NET_EM_MOSAIC_TYPE(IntEnum):
    """
    马赛克类型; mosaic type
    """
    MOSAIC_UNKNOWN = 0,                         # 未知; unknown;
    MOSAIC_8 = 8,                               # [8x8大小] 马赛克; [8x8];
    MOSAIC_16 = 16,                             # [16x16大小] 马赛克; [16x16];
    MOSAIC_24 = 24,                             # [24x24大小] 马赛克; [24x24];
    MOSAIC_32 = 32,                             # [32x32大小] 马赛克; [32x32];

class EM_PTZ_UNSUPPORT_DIRECTION(IntEnum):
    """
    云台不支持的转动方向; UnSupport Directions
    """
    UNKNOWN = 0,                                # 未知; unknown;
    UP = 1,                                     # 上; up;
    DOWN = 2,                                   # 下; down;
    LEFT = 3,                                   # 左; left;
    RIGHT = 4,                                  # 右; right;
    LEFTUP = 5,                                 # 左上; leftup;
    RIGHTUP = 6,                                # 右上; rightup;
    LEFTDOWN = 7,                               # 左下; leftdown;
    RIGHTDOWN = 8,                              # 右下; rightdown;

class NET_VOLUME_TYPE(IntEnum):
    """
    卷类型枚举; volume type enumeration
    """
    ALL = 0,                                    # 所有卷; all volume;
    PHYSICAL = 1,                               # 物理卷; physical volume;
    RAID = 2,                                   # Raid卷; Raid volume;
    VOLUME_GROUP = 3,                           # VG虚拟卷组; VG virtual volume;
    ISCSI = 4,                                  # iSCSI卷; iSCSI volume;
    INVIDUAL_PHY = 5,                           # 独立物理卷（这个物理盘,没有加入到, RAID,虚拟卷组等等组中）; independent physical volume, this physical volume, is not added into, RAID, virtual volume group,;
    GLOBAL_SPARE = 6,                           # 全局热备卷; global hot spare volume;
    NAS = 7,                                    # NAS盘(包括FTP, SAMBA, NFS); NAS volume(include FTP, SAMBA, NFS);
    INVIDUAL_RAID = 8,                          # 独立RAID卷（指没有加入到，虚拟卷组等组中）; independent raid volume, is not added into virtual volume group.;
    MAX = 9,

class EM_STORAGE_DISK_POWERMODE(IntEnum):
    """
    hard disk power mode; 硬盘电源状态
    """
    UNKNOWN = 0,                                # UNKnown状态（不是以下状态中的值）; UNKnown;
    NONE = 1,                                   # 未知状态; none;
    ACTIVE = 2,                                 # 活动状态; Active;
    STANDBY = 3,                                # 休眠状态; StandBy;
    IDLE = 4,                                   # 空闲状态; Idle;

class EM_STORAGE_DISK_PREDISKCHECK(IntEnum):
    """
    硬盘预检状态(配合磁盘预检功能使用); pre disk check(EVS)
    """
    UNKNOWN = 0,                                # UnKnown状态; UnKnown;
    GOOD = 1,                                   # 硬盘读速度到120以上,smart信息里有少量的错误,其他无任何错误.; good,read rate up to 120,,smart have a little error,other noerror.;
    WARN = 2,                                   # cmd信息里有少量错误记录,smart信息有错误记录; warn,cmd have a little error,smart have error;
    ERROR = 3,                                  # cmd信息有错误记录,smart信息由错误记录.坏扇区有坏扇区记录; error,cmd have error,smart have error.have bad sector;
    WILLFAIL = 4,                               # 硬盘速度比较低64M以下.cmd信息有错误记录,smart信息由错误记录.坏扇区有坏扇区记录; willfail,hard disk rate lower than 64M.cmd have error,smart have error.have bad sector;
    FAIL = 5,                                   # 硬盘返回错误; hard disk return fail;
    NONE = 6,                                   # 未知状态; none;
    BECHECK = 7,                                # 正在查询中状态; checking;
    CHECKFAIL = 8,                              # 查询失败状态; check fail;

class EM_TEMPERATUREEX_TYPE(IntEnum):
    """
    温度类型; temperature type
    """
    UNKNOWN = 0,                                # 未知; Unknown;
    ALL = 1,                                    # 全部; ALL;
    POWER = 2,                                  # 电源; Power;
    CABINET = 3,                                # 机柜; Cabinet;
    GLOBAL = 4,                                 # 环境; Global;
    MAINBOARD = 5,                              # 主板; Mainboard;
    CARD = 6,                                   # 子卡; Sub card;
    BACKBOARD = 7,                              # 背板; Backboard;
    CPU = 8,                                    # 处理器; CPU;

class NET_THREE_STATUS_BOOL(IntEnum):
    """
    三态布尔类型; Tri-state boolean type
    """
    BOOL_STATUS_FALSE = 0,
    BOOL_STATUS_TRUE = 1,
    BOOL_STATUS_UNKNOWN = 2,                    # 未知; unknown;

class EM_BOAT_CARGO_TYPE(IntEnum):
    """
    载货状态;Cargo status
    """
    BOAT_CARGO_TYPE_UNKNOWN = 0,                # 未知;unknown
    BOAT_CARGO_TYPE_EMPTY = 1,                  # 空载状态;Empty state
    BOAT_CARGO_TYPE_LOAD = 2,                   # 正常载货状态;Normal loading status
    BOAT_CARGO_TYPE_OVERLOAD = 3,               # 超载状态;Overload state

class EM_DATE_SOURCE(IntEnum):
    """
    数据来源; Data Sources
    """
    EM_DATE_SOURCE_GPS = 0,                     # GPS; GPS;
    EM_DATE_SOURCE_INERTIALNAVIGATION = 1,      # 惯性导航数据; inertial navigation date;

class EM_NET_VIFORMAT_TYPE(IntEnum):
    """
    采集源分辨率
    Vi Format
    """
    EM_NET_VIFORMAT_TYPE_UNKNOWN = -1,          # 未知;unknown;
    EM_NET_VIFORMAT_TYPE_NORMAL = 0,            # 表示正常分辨率;normal;
    EM_NET_VIFORMAT_TYPE_UNSUPPORT = 1,         # 表示不支持的分辨率;unsupport;
    EM_NET_VIFORMAT_TYPE_NOT_CONNECTED = 2,     # 表示未接采集源;not connected;

class NET_STREAM_TYPE(IntEnum):
    """
    视频码流类型; Video stream type
    """
    NET_EM_STREAM_ERR = 0,                      # 其它; Others;
    NET_EM_STREAM_MAIN = 1,                     # "Main"-主码流; "Main"-Main stream;
    NET_EM_STREAM_EXTRA_1 = 2,                  # "Extra1"-辅码流1; "Extra1"-Extra stream 1;
    NET_EM_STREAM_EXTRA_2 = 3,                  # "Extra2"-辅码流2; "Extra2"-Extra stream 2;
    NET_EM_STREAM_EXTRA_3 = 4,                  # "Extra3"-辅码流3; "Extra3"-Extra stream 3;
    NET_EM_STREAM_SNAPSHOT = 5,                 # "Snapshot"-抓图码流; "Snapshot"-Snap bit stream;
    NET_EM_STREAM_OBJECT = 6,                   # "Object"-物体流; "Object"-Object stream;
    NET_EM_STREAM_AUTO = 7,                     # "Auto"-自动选择合适码流; "Auto";
    NET_EM_STREAM_PREVIEW = 8,                  # "Preview"-预览裸数据码流; "Preview";
    NET_EM_STREAM_NONE = 9,                     # 无视频码流(纯音频); No video stream (audio only);

class EM_FILE_QUERY_TYPE(IntEnum):
    """
    media文件查询条件; media file query conditions
    """
    FILE_QUERY_TRAFFICCAR = 0,                  # 交通车辆信息,对应结构体为MEDIA_QUERY_TRAFFICCAR_PARAM; Traffic vehicle information, the corresponding structure is MEDIA_QUERY_TRAFFICCAR_PARAM
    FILE_QUERY_FILE = 4,                        # 文件信息对应 NET_IN_MEDIA_QUERY_FILE 和 NET_OUT_MEDIA_QUERY_FILE; File information corresponding to net_ IN_ MEDIA_ QUERY_ File and net_ OUT_ MEDIA_ QUERY_ FILE
    FILE_QUERY_TRAFFICCAR_EX = 5,               # 交通车辆信息, 扩展DH_FILE_QUERY_TRAFFICCAR, 支持更多的字段，对应结构体为MEDIA_QUERY_TRAFFICCAR_PARAM_EX; Traffic vehicle information, extend DH_FILE_QUERY_TRAFFICCAR, support more fields, the corresponding structure is MEDIA_QUERY_TRAFFICCAR_PARAM_EX

class EM_SAFE_BELT_STATE(IntEnum):
    """
    安全带状态; seat belt status
    """
    EM_SAFE_BELT_UNKNOWN = 0,                   # 未知; unknown;
    EM_SAFE_BELT_OTHER = 1,                     # 未识别; unidentified;
    EM_SAFE_BELT_WITH = 2,                      # 有安全带; with safe belt;
    EM_SAFE_BELT_WITHOUT = 3,                   # 无安全带; without safe belt;

class EM_CALLING_STATE(IntEnum):
    """
    打电话状态; call status
    """
    EM_CALLING_UNKNOWN = 0,                     # 未知; unknown;
    EM_CALLING_OTHER = 1,                       # 未识别; unidentified;
    EM_CALLING_NO = 2,                          # 未打电话; not calling;
    EM_CALLING_YES = 3,                         # 打电话; calling;

class EM_ATTACHMENT_TYPE(IntEnum):
    """
    车内饰品类型; Types of interior accessories
    """
    EM_ATTACHMENT_UNKNOWN = 0,                  # 未知; unknown;
    EM_ATTACHMENT_OTHER = 1,                    # 其他类型; other;
    EM_ATTACHMENT_FURNITURE = 2,                # 摆件; furniture;
    EM_ATTACHMENT_PENDANT = 3,                  # 挂件; pendant;
    EM_ATTACHMENT_TISSUEBOX = 4,                # 纸巾盒; tissue box;
    EM_ATTACHMENT_DANGER = 5,                   # 危险品; danger;
    EM_ATTACHMENT_PERFUMEBOX = 6,               # 香水; perfume box;

class EM_CATEGORY_TYPE(IntEnum):
    """
    车辆类型; Vehicle Type
    """
    EM_CATEGORY_UNKNOWN = 0,                    # 未知; Unknown;
    EM_CATEGORY_OTHER = 1,                      # 其他; Other;
    EM_CATEGORY_MOTOR = 2,                      # 机动车; Motor;
    EM_CATEGORY_BUS = 3,                        # 公交车; Bus;
    EM_CATEGORY_UNLICENSED_MOTOR = 4,           # 无牌机动车; UnlicensedMotor;
    EM_CATEGORY_LARGE_CAR = 5,                  # 大型汽车; LargeCar;
    EM_CATEGORY_MICRO_CAR = 6,                  # 小型汽车; MicroCar;
    EM_CATEGORY_EMBASSY_CAR = 7,                # 使馆汽车; EmbassyCar;
    EM_CATEGORY_MARGINAL_CAR = 8,               # 领馆汽车; MarginalCar;
    EM_CATEGORY_AREAOUT_CAR = 9,                # 境外汽车; AreaoutCar;
    EM_CATEGORY_FOREIGN_CAR = 10,               # 外籍汽车; ForeignCar;
    EM_CATEGORY_FARMTRANSMIT_CAR = 11,          # 农用运输车; FarmTransmitCar;
    EM_CATEGORY_TRACTOR = 12,                   # 拖拉机; Tractor;
    EM_CATEGORY_TRAILER = 13,                   # 挂车; Trailer;
    EM_CATEGORY_COACH_CAR = 14,                 # 教练汽车; CoachCar;
    EM_CATEGORY_TRIAL_CAR = 15,                 # 试验汽车; TrialCar;
    EM_CATEGORY_TEMPORARY_ENTRY_CAR = 16,       # 临时入境汽车; TemporaryEntryCar;
    EM_CATEGORY_TEMPORARY_ENTRY_MOTORCYCLE = 17,    # 临时入境摩托; TemporaryEntryMotorcycle;
    EM_CATEGORY_TEMPORARY_STEER_CAR = 18,       # 临时行驶车; TemporarySteerCar;
    EM_CATEGORY_LARGE_TRUCK = 19,               # 大货车; LargeTruck;
    EM_CATEGORY_MID_TRUCK = 20,                 # 中货车; MidTruck;
    EM_CATEGORY_MICRO_TRUCK = 21,               # 小货车; MicroTruck;
    EM_CATEGORY_MICROBUS = 22,                  # 面包车; Microbus;
    EM_CATEGORY_SALOON_CAR = 23,                # 轿车; SaloonCar;
    EM_CATEGORY_CARRIAGE = 24,                  # 小轿车; Carriage;
    EM_CATEGORY_MINI_CARRIAGE = 25,             # 微型轿车; MiniCarriage;
    EM_CATEGORY_SUV_MPV = 26,                   # SUV或者MPV; SUV or MPV;
    EM_CATEGORY_SUV = 27,                       # SUV; SUV;
    EM_CATEGORY_MPV = 28,                       # MPV; MPV;
    EM_CATEGORY_PASSENGER_CAR = 29,             # 客车; PassengerCar;
    EM_CATEGORY_MOTOR_BUS = 30,                 # 大客; MotorBus;
    EM_CATEGORY_MID_PASSENGER_CAR = 31,         # 中客车; MidPassengerCar;
    EM_CATEGORY_MINI_BUS = 32,                  # 小客车; MiniBus;
    EM_CATEGORY_PICKUP = 33,                    # 皮卡车; Pickup;
    EM_CATEGORY_OILTANK_TRUCK = 34,             # 油罐车; OilTankTruck;
    EM_CATEGORY_TANK_CAR = 35,                  # 危化品车辆; TankCar;
    EM_CATEGORY_SLOT_TANK_CAR = 36,             # 槽罐车; SlotTankCar;
    EM_CATEGORY_DREGS_CAR = 37,                 # 渣土车; DregsCar;
    EM_CATEGORY_CONCRETE_MIXER_TRUCK = 38,      # 混凝土搅拌车; ConcreteMixerTruck;
    EM_CATEGORY_TAXI = 39,                      # 出租车; Taxi;
    EM_CATEGORY_POLICE = 40,                    # 警车; Police;
    EM_CATEGORY_AMBULANCE = 41,                 # 救护车; Ambulance;
    EM_CATEGORY_GENERAL = 42,                   # 普通车; General;
    EM_CATEGORY_WATERING_CAR = 43,              # 洒水车; WateringCar;
    EM_CATEGORY_FIRE_ENGINE = 44,               # 消防车; FireEngine;
    EM_CATEGORY_MACHINE_TRUCK = 45,             # 工程车; MachineshopTruck;
    EM_CATEGORY_POWER_LOT_VEHICLE = 46,         # 粉粒物料车; PowerLotVehicle;
    EM_CATEGORY_SUCTION_SEWAGE_TRUCK = 47,      # 吸污车; SuctionSewageTruck;
    EM_CATEGORY_NORMAL_TANK_TRUCK = 48,         # 普通罐车; NormalTankTrunk;
    EM_CATEGORY_SCHOOL_BUS = 49,                # 校车; School Bus;
    EM_CATEGORY_EXCAVATOR = 50,                 # 挖掘车; Excavator;
    EM_CATEGORY_BULLDOZER = 51,                 # 推土车; Bulldozer;
    EM_CATEGORY_CRANE = 52,                     # 吊车; Cranz;
    EM_CATEGORY_PIMP_TRUCK = 53,                # 泵车; PimpTruck;
    EM_CATEGORY_FORKLIFT = 54,                  # 叉车;Forklift;

class EM_RECORD_SNAP_FLAG_TYPE(IntEnum):
    """
    文件类型; file type
    """
    FLAG_TYPE_TIMING = 0,                       # 定时文件; Schele;
    FLAG_TYPE_MANUAL = 1,                       # 手动文件; Manual;
    FLAG_TYPE_MARKED = 2,                       # 重要文件; Important;
    FLAG_TYPE_EVENT = 3,                        # 事件文件; Event;
    FLAG_TYPE_MOSAIC = 4,                       # 合成图片; Combined;
    FLAG_TYPE_CUTOUT = 5,                       # 抠图图片; Cut;
    FLAG_TYPE_LEAVE_WORD = 6,                   # 留言文件; Message;
    FLAG_TYPE_TALKBACK_LOCAL_SIDE = 7,          # 对讲本地方文件; Talk Local;
    FLAG_TYPE_TALKBACK_REMOTE_SIDE = 8,         # 对讲远程方文件; Talk Remote;
    FLAG_TYPE_SYNOPSIS_VIDEO = 9,               # 浓缩视频; Compressed Video;
    FLAG_TYPE_ORIGINAL_VIDEO = 10,              # 原始视频; Original Video;
    FLAG_TYPE_PRE_ORIGINAL_VIDEO = 11,          # 已经预处理的原始视频; Processed;
    FLAG_TYPE_BLACK_PLATE = 12,                 # 禁止名单图片; Blocklist Picture;
    FLAG_TYPE_ORIGINAL_PIC = 13,                # 原始图片; Original Picture;
    FLAG_TYPE_CARD = 14,                        # 卡号录像; card no. record;
    FLAG_TYPE_MAX = 128,

class EM_SMOKING_STATE(IntEnum):
    """
    是否抽烟; smoke status
    """
    EM_SMOKING_UNKNOWN = 0,                     # 未知; unknown;
    EM_SMOKING_NO = 1,                          # 未抽烟; not smoking;
    EM_SMOKING_YES = 2,                         # 抽烟; smoking;

class EM_UPLOAD_FLAG(IntEnum):
    """
    上传结果; Upload results
    """
    EM_UPLOAD_FLAG_UNKNOWN = 0,                 # 未知; Unknown;
    EM_UPLOAD_FLAG_SUCCEED = 1,                 # 成功; Succeed;
    EM_UPLOAD_FLAG_FAILED = 2,                  # 失败; Failed;

class EM_NET_RECORD_TYPE(IntEnum):
    """
    查询记录对应的条件枚举; Find record type
    """
    UNKNOWN = 0,
    TRAFFICREDLIST = 1,                         # 交通允许名单账户记录,查询条件对应 FIND_RECORD_TRAFFICREDLIST_CONDITION 结构体,记录信息对应 NET_TRAFFIC_LIST_RECORD 结构体; Traffic Allow list account record,search criteria corresponding to FIND_RECORD_TRAFFICREDLIST_CONDITION structure,record info corresponding to NET_TRAFFIC_LIST_RECORD structure;
    TRAFFICBLACKLIST = 2,                       # 交通禁止名单账号记录,查询条件对应 FIND_RECORD_TRAFFICREDLIST_CONDITION 结构体,记录信息对应 NET_TRAFFIC_LIST_RECORD 结构体; Traffic block list account record,search criteria corresponding to FIND_RECORD_TRAFFICREDLIST_CONDITION structure,record info corresponding to NET_TRAFFIC_LIST_RECORD structure;
    BURN_CASE = 3,                              # 刻录案件记录,查询条件对应 FIND_RECORD_BURN_CASE_CONDITION 结构体,记录信息对应 NET_BURN_CASE_INFO 结构体; burning case record,search criteria corresponding to FIND_RECORD_BURN_CASE_CONDITION structure,record info corresponding to NET_BURN_CASE_INFO structure;
    ACCESSCTLCARD = 4,                          # 门禁卡,查询条件对应 NET_A_FIND_RECORD_ACCESSCTLCARD_CONDITION 结构体,记录信息对应 NET_RECORDSET_ACCESS_CTL_CARD 结构体; access control card,search criteria corresponding to NET_A_FIND_RECORD_ACCESSCTLCARD_CONDITION structure,record info corresponding to NET_RECORDSET_ACCESS_CTL_CARD structure;
    ACCESSCTLPWD = 5,                           # 门禁密码,查询条件对应 FIND_RECORD_ACCESSCTLPWD_CONDITION 结构体,记录信息对应 NET_RECORDSET_ACCESS_CTL_PWD; access control password,search criteria corresponding to FIND_RECORD_ACCESSCTLPWD_CONDITION structure,record info corresponding to NET_RECORDSET_ACCESS_CTL_PWD;
    ACCESSCTLCARDREC = 6,                       # 门禁出入记录（必须同时按卡号和时间段查询,建议用NET_RECORD_ACCESSCTLCARDREC_EX查询）,查询条件对应 FIND_RECORD_ACCESSCTLCARDREC_CONDITION 结构体,记录信息对应 NET_RECORDSET_ACCESS_CTL_CARDREC 结构体; access control in/out record,search criteria corresponding to FIND_RECORD_ACCESSCTLCARDREC_CONDITION structure,record info corresponding to;
    ACCESSCTLHOLIDAY = 7,                       # 假日记录集,查询条件对应 FIND_RECORD_ACCESSCTLHOLIDAY_CONDITION 结构体,记录信息对应 NET_RECORDSET_HOLIDAY 结构体; holiday record set,search criteria corresponding to FIND_RECORD_ACCESSCTLHOLIDAY_CONDITION structure,record info corresponding to;
    TRAFFICFLOW_STATE = 8,                      # 查询交通流量记录,查询条件对应 FIND_RECORD_TRAFFICFLOW_CONDITION 结构体,记录信息对应 NET_RECORD_TRAFFIC_FLOW_STATE 结构体; search Traffic flow record,search criteria corresponding to FIND_RECORD_TRAFFICFLOW_CONDITION structure,record info corresponding to NET_RECORD_TRAFFIC_FLOW_STATE structure;
    VIDEOTALKLOG = 9,                           # 通话记录,查询条件对应 FIND_RECORD_VIDEO_TALK_LOG_CONDITION 结构体,记录信息对应 NET_RECORD_VIDEO_TALK_LOG 结构体; call record,search criteria corresponding to FIND_RECORD_VIDEO_TALK_LOG_CONDITION structure,record info corresponding to NET_RECORD_VIDEO_TALK_LOG structure;
    REGISTERUSERSTATE = 10,                     # 状态记录,查询条件对应 FIND_RECORD_REGISTER_USER_STATE_CONDITION 结构体,记录信息对应 NET_RECORD_REGISTER_USER_STATE 结构体; status record,search criteria corresponding to FIND_RECORD_REGISTER_USER_STATE_CONDITION structure,record info corresponding to NET_RECORD_REGISTER_USER_STATE structure;
    VIDEOTALKCONTACT = 11,                      # 联系人记录,查询条件对应 FIND_RECORD_VIDEO_TALK_CONTACT_CONDITION 结构体,记录信息对应 NET_RECORD_VIDEO_TALK_CONTACT 结构体; contact record,search criteria corresponding to FIND_RECORD_VIDEO_TALK_CONTACT_CONDITION structure,record info corresponding to NET_RECORD_VIDEO_TALK_CONTACT structure;
    ANNOUNCEMENT = 12,                          # 公告记录,查询条件对应 FIND_RECORD_ANNOUNCEMENT_CONDITION 结构体,记录信息对应 NET_RECORD_ANNOUNCEMENT_INFO 结构体; Record info corresponding to structure NET_RECORD_ANNOUNCEMENT_INFO,No search criteria;
    ALARMRECORD = 13,                           # 报警记录,查询条件对应 FIND_RECORD_ALARMRECORD_CONDITION 结构体,记录信息对应 NET_RECORD_ALARMRECORD_INFO 结构体; Record info corresponding to structure NET_RECORD_ALARMRECORD_INFO,No search criteria;
    COMMODITYNOTICE = 14,                       # 下发商品记录,查询条件对应 FIND_RECORD_COMMODITY_NOTICE_CONDITION 结构体,记录信息对应 NET_RECORD_COMMODITY_NOTICE 结构体; Issue commodiy record,Record info corresponding to structure NET_RECORD_COMMODITY_NOTICE;
    HEALTHCARENOTICE = 15,                      # 就诊信息记录,查询条件对应 FIND_RECORD_HEALTH_CARE_NOTICE_CONDITION 结构体,记录信息对应 NET_RECORD_HEALTH_CARE_NOTICE 结构体; Medical info,Record info corresponding to structure NET_RECORD_HEALTH_CARE_NOTICE;
    ACCESSCTLCARDREC_EX = 16,                   # 门禁出入记录(可选择部分条件查询,建议替代NET_RECORD_ACCESSCTLCARDREC),查询条件对应 FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX 结构体,记录信息对应 NET_RECORDSET_ACCESS_CTL_CARDREC 结构体; A&C entry-exit record(can select some critera to search. Please replace NET_RECORD_ACCESSCTLCARDREC),Search criteria corresponding to structure FIND_RECORD_ACCESSCTLCARDREC_CONDITION_EX,Record info corresponding to structure NET_RECORDSET_ACCESS_CTL_CARDREC;
    GPS_LOCATION = 17,                          # GPS位置信息记录, 只实现import和clear,记录信息对应 NET_RECORD_GPS_LOCATION_INFO 结构体; GPS position information reocrd, support import and clear only.,Record info corresponding to structure NET_RECORD_GPS_LOCATION_INFO;
    RESIDENT = 18,                              # 公租房租户信息,查询条件对应 FIND_RECORD_RESIDENT_CONDTION结构体,记录信息对应 NET_RECORD_RESIDENT_INFO 结构体; resident info,Record info corresponding to structure FIND_RECORD_RESIDENT_CONDTION,Record info corresponding to NET_RECORD_RESIDENT_INFO;
    SENSORRECORD = 19,                          # 监测量数据记录,查询条件对应 FIND_RECORD_SENSORRECORD_CONDITION 结构体,记录信息对应 NET_RECORD_SENSOR_RECORD 结构体; sensor record,Search criteria corresponding to structure FIND_RECORD_SENSORRECORD_CONDITION,Record info corresponding to structure NET_RECORD_SENSOR_RECORD;
    ACCESSQRCODE = 20,                          # 开门二维码记录集,记录信息对应 NET_RECORD_ACCESSQRCODE_INFO 结构体; AccessQRCode record,Record info corresponding to structure NET_RECORD_ACCESSQRCODE_INFO;
    ELECTRONICSTAG = 21,                        # 电子车牌查询,查询条件对应FIND_RECORD_ELECTRONICSTAG_CONDITION 结构体,记录信息对应NET_RECORD_ELECTRONICSTAG_INFO 结构体; electronic tag info record,Search criteria corresponding to structure FIND_RECORD_ELECTRONICSTAG_CONDITION,Record info corresponding to NET_RECORD_ELECTRONICSTAG_INFO;
    ACCESS_BLUETOOTH = 22,                      # 蓝牙开门记录集,查询条件对应 FIND_RECORD_ACCESS_BLUETOOTH_INFO_CONDITION 结构体,记录信息对应 NET_RECORD_ACCESS_BLUETOOTH_INFO 结构体; Access blue tooth record,Search blue tooth access record corresponding to structure FIND_RECORD_ACCESS_BLUETOOTH_INFO_CONDITION,Record info corresponding to structure NET_RECORD_ACCESS_BLUETOOTH_INFO;
    ACCESS_ALARMRECORD = 23,                    # 门禁报警记录集,查询条件对应 FIND_NET_RECORD_ACCESS_ALARMRECORD_INFO_CONDITION 结构体,记录信息对应 NET_RECORD_ACCESS_ALARMRECORD_INFO 结构体; Accesscontrol alarm record,Search condition：null,Record info corresponding to NET_RECORD_ACCESS_ALARMRECORD_INFO;
    ACCESS_DOORSTATUS = 24,                     # 开关门事件记录,查询条件对应 FIND_RECORD_ACCESS_DOORSTATUS_INFO_CONDITION 结构体,记录信息对应 NET_RECORD_ACCESS_DOORSTATUS_INFO 结构体; AccessControl door status record,Search criteria corresponding to structure FIND_RECORD_ACCESS_DOORSTATUS_INFO_CONDITION,Record info corresponding to NET_RECORD_ACCESS_DOORSTATUS_INFO;
    ACCESSCTL_COMMON_PASSWORD = 25,             # 楼宇通用开门密码,查询条件对应 FIND_RECORD_ACCESS_CTL_COMMONPASSWORD_INFO_CONDITION 结构体,记录信息对应 NET_RECORD_ACCESS_CTL_COMMONPASSWORD_INFO 结构体; Common password for access control record,Search criteria corresponding to structure FIND_RECORD_ACCESS_CTL_COMMONPASSWORD_INFO_CONDITION,Record info corresponding to structure NET_RECORD_ACCESS_CTL_COMMONPASSWORD_INFO;
    ACCESS_MOBILE_PUSH_RESULT = 26,             # VTO设备推送信息记录,条件查询对应 FIND_RECORD_ACCESS_MOBILE_PUSH_RESULT_INFO_CONDITION 结构体,记录信息对应 NET_RECORD_ACCESS_MOBILE_PUSH_RESULT_INFO; VTO device push information record,Condition query corresponding to structure FIND_RECORD_ACCESS_MOBILE_PUSH_RESULT_INFO_CONDITION,Record information correspondence to structure NET_RECORD_ACCESS_MOBILE_PUSH_RESULT_INFO;
    HOSPITAL_USER = 27,                         # 医院人员信息表查询条件对应 FIND_RECORD_HOSPITAL_USER_CONDITION 结构体记录信息对应 NET_RECORD_HOSPITAL_USER_INFO 结构体;Hospital UserCondition query corresponding to structure FIND_RECORD_HOSPITAL_USER_CONDITIONRecord information correspondence to structure NET_RECORD_HOSPITAL_USER_INFO;
    HOSPITAL_DEVICE = 28,                       # 医院设备信息表查询条件对应 FIND_RECORD_HOSPITAL_DEVICE_CONDITION 结构体记录信息对应 NET_RECORD_HOSPITAL_DEVICE_INFO 结构体;Hospital DeviceCondition query corresponding to structure FIND_RECORD_HOSPITAL_DEVICE_CONDITIONRecord information correspondence to structure NET_RECORD_HOSPITAL_DEVICE_INFO;
    ACCESS_CONSUMPTION = 29,                    # 消费记录查询条件对应 FIND_RECORD_ACCESS_CTL_CONSUMPTION_INFO_CONDITION 结构体记录信息对应 NET_RECORD_ACCESS_CTL_CONSUMPTION_INFO 结构体;Consumption RecordCondition query corresponding to structure FIND_RECORD_ACCESS_CTL_CONSUMPTION_INFO_CONDITIONRecord information correspondence to structure NET_RECORD_ACCESS_CTL_CONSUMPTION_INFO;

class EM_RECORD_OPERATE_TYPE(IntEnum):
    """
    可用名单操作类型; Available List Action Types
    """
    NET_TRAFFIC_LIST_INSERT = 0,                # 增加记录操作(对应结构体 NET_INSERT_RECORD_INFO); Increase the record operation(Correspond to NET_INSERT_RECORD_INFO);
    NET_TRAFFIC_LIST_UPDATE = 1,                # 更新记录操作(对应结构体 NET_UPDATE_RECORD_INFO); Record update operation(Correspond to NET_UPDATE_RECORD_INFO);
    NET_TRAFFIC_LIST_REMOVE = 2,                # 删除记录操作(对应结构体 NET_REMOVE_RECORD_INFO); Delete the record operation(Correspond to NET_REMOVE_RECORD_INFO);
    NET_TRAFFIC_LIST_MAX = 3,

class EM_NET_PLATE_TYPE(IntEnum):
    """
    车牌类型; license plate type
    """
    NET_PLATE_TYPE_UNKNOWN = 0,
    NET_PLATE_TYPE_NORMAL = 1,                  # "Normal" 蓝牌黑牌; "Normal" Blue card black card;
    NET_PLATE_TYPE_YELLOW = 2,                  # "Yellow" 黄牌; "Yellow" yellow card;
    NET_PLATE_TYPE_DOUBLEYELLOW = 3,            # "DoubleYellow" 双层黄尾牌; "DoubleYellow" Double yellow back card;
    NET_PLATE_TYPE_POLICE = 4,                  # "Police" 警牌; "Police" Police card;
    NET_PLATE_TYPE_WJ = 5,
    NET_PLATE_TYPE_OUTERGUARD = 6,
    NET_PLATE_TYPE_DOUBLEOUTERGUARD = 7,
    NET_PLATE_TYPE_SAR = 8,                     # "SAR" 港澳特区号牌; "SAR" Hong Kong and Macao SAR plate;
    NET_PLATE_TYPE_TRAINNING = 9,               # "Trainning" 教练车号牌; "Trainning" Drivers Ed plate;
    NET_PLATE_TYPE_PERSONAL = 10,               # "Personal" 个性号牌; "Personal" Personality plate;
    NET_PLATE_TYPE_AGRI = 11,                   # "Agri" 农用牌; "Agri" Agri-using card;
    NET_PLATE_TYPE_EMBASSY = 12,                # "Embassy" 使馆号牌; "Embassy" The embassy of plate;
    NET_PLATE_TYPE_MOTO = 13,                   # "Moto" 摩托车号牌; "Moto" Motorcycle plate;
    NET_PLATE_TYPE_TRACTOR = 14,                # "Tractor" 拖拉机号牌; "Tractor" The tractor plate;
    NET_PLATE_TYPE_OFFICIALCAR = 15,            # "OfficialCar" 公务车; "OfficialCar" officer's car;
    NET_PLATE_TYPE_PERSONALCAR = 16,            # "PersonalCar" 私家车; "PersonalCar" private car;
    NET_PLATE_TYPE_WARCAR = 17,
    NET_PLATE_TYPE_OTHER = 18,                  # "Other" 其他号牌; "Other" The other plate;
    NET_PLATE_TYPE_CIVILAVIATION = 19,          # "Civilaviation" 民航号牌; "Civilaviation" Civilaviation;
    NET_PLATE_TYPE_BLACK = 20,                  # "Black" 黑牌; "Black";
    NET_PLATE_TYPE_PURENEWENERGYMICROCAR = 21,  # "PureNewEnergyMicroCar" 纯电动新能源小车; "PureNewEnergyMicroCar" pure new energy micro car;
    NET_PLATE_TYPE_MIXEDNEWENERGYMICROCAR = 22, # "MixedNewEnergyMicroCar" 混合新能源小车; "MixedNewEnergyMicroCar" mixed new energy micro car;
    NET_PLATE_TYPE_PURENEWENERGYLARGECAR = 23,  # "PureNewEnergyLargeCar" 纯电动新能源大车; "PureNewEnergyLargeCar" pure new energy large car;
    NET_PLATE_TYPE_MIXEDNEWENERGYLARGECAR = 24, # "MixedNewEnergyLargeCar" 混合新能源大车; "MixedNewEnergyLargeCar" mixed new energy large car;
    NET_PLATE_TYPE_HONGKONG = 25,               # "Hongkong" 香港号牌; "Hongkong" Hong Kong number plate;
    NET_PLATE_TYPE_MAKAO = 26,                  # "Makao" 澳门号牌; "Makao" Macao number plate;

class EM_NET_PLATE_COLOR_TYPE(IntEnum):
    """
    车牌颜色; license plate color
    """
    NET_PLATE_COLOR_OTHER = 0,                  # 其他颜色; other colors;
    NET_PLATE_COLOR_BLUE = 1,                   # 蓝色 "Blue"; blue "Blue";
    NET_PLATE_COLOR_YELLOW = 2,                 # 黄色 "Yellow"; yellow "Yellow";
    NET_PLATE_COLOR_WHITE = 3,                  # 白色 "White"; white "White";
    NET_PLATE_COLOR_BLACK = 4,                  # 黑色 "Black"; black "Black";
    NET_PLATE_COLOR_YELLOW_BOTTOM_BLACK_TEXT = 5,    # 黄底黑字 "YellowbottomBlackText"; Yellow Bottom Positive Figure "YellowbottomBlackText";
    NET_PLATE_COLOR_BLUE_BOTTOM_WHITE_TEXT = 6, # 蓝底白字 "BluebottomWhiteText"; blue-mask LCD";
    NET_PLATE_COLOR_BLACK_BOTTOM_WHITE_TEXT = 7,    # 黑底白字 "BlackBottomWhiteText"; White on Black "BlackBottomWhiteText";
    NET_PLATE_COLOR_SHADOW_GREEN = 8,           # 渐变绿 "ShadowGreen"; Shadow Green;
    NET_PLATE_COLOR_YELLOW_GREEN = 9,           # 黄绿双拼 "YellowGreen"; YellowGreen;
    NET_PLATE_COLOR_UNKNOW = 10,                # 未知颜色 "Unknow";unknow color "Unknow"
    NET_PLATE_COLOR_GREEN = 11,                 # 绿色 "Green";green "Green"
    NET_PLATE_COLOR_RED = 12,                   # 红色 "Red";red "Red"
    NET_PLATE_COLOR_ORANGE = 13,                # 橙色 "Orange";Orange "Orange"

class EM_DETECT_OBJECT_TYPE(IntEnum):
    """
    目标类型
    Detect object type
    """
    EM_DETECT_OBJECT_TYPE_UNKNOWN = 0,          # 未知;Unknown;
    EM_DETECT_OBJECT_TYPE_FACE = 1,             # 人脸;Face;
    EM_DETECT_OBJECT_TYPE_VEHICLE = 2,          # 车辆;Vehicle;
    EM_DETECT_OBJECT_TYPE_STRUCTLIZE = 3,       # 结构化;Struct Lize;

class EM_DETECT_PROCESS_TYPE(IntEnum):
    """
    处理类型
    Detect process type
    """
    EM_DETECT_PROCESS_TYPE_UNKNOWN = 0,         # 当此值为0或者不存在，就做检测，与EM_DETECT_PROCESS_TYPE_DETECT一致;Unknwon;
    EM_DETECT_PROCESS_TYPE_FEATURE = 1,         # 提取特征;Extract feature;
    EM_DETECT_PROCESS_TYPE_ATTRIBUTE = 2,       # 提取属性;Extract attribute;
    EM_DETECT_PROCESS_TYPE_DETECT = 3,          # 检测;Detection;

class EM_NET_VEHICLE_TYPE(IntEnum):
    """
    车辆类型; Vehicle Type
    """
    NET_VEHICLE_TYPE_UNKNOW = 0,                # 未知类型; unknown type;
    NET_VEHICLE_TYPE_MOTOR = 1,                 # "Motor" 机动车; "Motor" Motor vehicles";
    NET_VEHICLE_TYPE_NON_MOTOR = 2,             # "Non-Motor"非机动车; "Non-Motor"non-Motor vehicles";
    NET_VEHICLE_TYPE_BUS = 3,                   # "Bus"公交车; "Bus"bus;
    NET_VEHICLE_TYPE_BICYCLE = 4,               # "Bicycle" 自行车; "Bicycle"Bicycle;
    NET_VEHICLE_TYPE_MOTORCYCLE = 5,            # "Motorcycle"摩托车; "Motorcycle";
    NET_VEHICLE_TYPE_UNLICENSEDMOTOR = 6,       # "UnlicensedMotor": 无牌机动车; "UnlicensedMotor": A motor vehicle without a license;
    NET_VEHICLE_TYPE_LARGECAR = 7,              # "LargeCar" 大型汽车; "LargeCar" LargeCar;
    NET_VEHICLE_TYPE_MICROCAR = 8,              # "MicroCar" 小型汽车; "MicroCar" MicroCar;
    NET_VEHICLE_TYPE_EMBASSYCAR = 9,            # "EmbassyCar" 使馆汽车; "EmbassyCar" EmbassyCa;
    NET_VEHICLE_TYPE_MARGINALCAR = 10,          # "MarginalCar" 领馆汽车; "MarginalCar" MarginalCar;
    NET_VEHICLE_TYPE_AREAOUTCAR = 11,           # "AreaoutCar" 境外汽车; "AreaoutCar" AreaoutCar;
    NET_VEHICLE_TYPE_FOREIGNCAR = 12,           # "ForeignCar" 外籍汽车; "ForeignCar" ForeignCar;
    NET_VEHICLE_TYPE_DUALTRIWHEELMOTORCYCLE = 13,    # "DualTriWheelMotorcycle"两、三轮摩托车; "DualTriWheelMotorcycle"Two or three rounds of motorcycle;
    NET_VEHICLE_TYPE_LIGHTMOTORCYCLE = 14,      # "LightMotorcycle" 轻便摩托车; "LightMotorcycle" light motorcycle;
    NET_VEHICLE_TYPE_EMBASSYMOTORCYCLE = 15,    # "EmbassyMotorcycle "使馆摩托车; "EmbassyMotorcycle "The embassy of the motorcycle;
    NET_VEHICLE_TYPE_MARGINALMOTORCYCLE = 16,   # "MarginalMotorcycle "领馆摩托车; "MarginalMotorcycle "Consulate motorcycle;
    NET_VEHICLE_TYPE_AREAOUTMOTORCYCLE = 17,    # "AreaoutMotorcycle "境外摩托车; "AreaoutMotorcycle "Outside the motorcycle;
    NET_VEHICLE_TYPE_FOREIGNMOTORCYCLE = 18,    # "ForeignMotorcycle "外籍摩托车; "ForeignMotorcycle "Foreign motorcycle;
    NET_VEHICLE_TYPE_FARMTRANSMITCAR = 19,      # "FarmTransmitCar" 农用运输车; "FarmTransmitCar" agricultural vehicle;
    NET_VEHICLE_TYPE_TRACTOR = 20,              # "Tractor" 拖拉机; "Tractor" tractor;
    NET_VEHICLE_TYPE_TRAILER = 21,              # "Trailer" 挂车; "Trailer" trailer;
    NET_VEHICLE_TYPE_COACHCAR = 22,             # "CoachCar"教练汽车; "CoachCar "Car coach;
    NET_VEHICLE_TYPE_COACHMOTORCYCLE = 23,      # "CoachMotorcycle "教练摩托车; "CoachMotorcycle " coach Motorcycle;
    NET_VEHICLE_TYPE_TRIALCAR = 24,             # "TrialCar" 试验汽车; "TrialCar" trial car;
    NET_VEHICLE_TYPE_TRIALMOTORCYCLE = 25,      # "TrialMotorcycle "试验摩托车; "TrialMotorcycle "Test motorcycle;
    NET_VEHICLE_TYPE_TEMPORARYENTRYCAR = 26,    # "TemporaryEntryCar"临时入境汽车; "TemporaryEntryCar"Temporary entry vehicle;
    NET_VEHICLE_TYPE_TEMPORARYENTRYMOTORCYCLE = 27,    # "TemporaryEntryMotorcycle"临时入境摩托车; "TemporaryEntryMotorcycle"Temporary entry of motorcycle;
    NET_VEHICLE_TYPE_TEMPORARYSTEERCAR = 28,    # "TemporarySteerCar"临时行驶车; "TemporarySteerCar"Temporary driving car;
    NET_VEHICLE_TYPE_PASSENGERCAR = 29,         # "PassengerCar" 客车; "PassengerCar" passenger car;
    NET_VEHICLE_TYPE_LARGETRUCK = 30,           # "LargeTruck" 大货车; "LargeTruck" LargeTruck;
    NET_VEHICLE_TYPE_MIDTRUCK = 31,             # "MidTruck" 中货车; "MidTruck" MidTruck;
    NET_VEHICLE_TYPE_SALOONCAR = 32,            # "SaloonCar" 轿车; "SaloonCar" SaloonCar;
    NET_VEHICLE_TYPE_MICROBUS = 33,             # "Microbus"面包车; "Microbus" Microbus;
    NET_VEHICLE_TYPE_MICROTRUCK = 34,           # "MicroTruck"小货车; "MicroTruck" MicroTruck;
    NET_VEHICLE_TYPE_TRICYCLE = 35,             # "Tricycle"三轮车; "Tricycle" Tricycle;
    NET_VEHICLE_TYPE_PASSERBY = 36,             # "Passerby" 行人; "Passerby" Passerby;

class EM_NET_VEHICLE_COLOR_TYPE(IntEnum):
    """
    车身颜色; the color of car
    """
    NET_VEHICLE_COLOR_OTHER = 0,                # 其他颜色; other color;
    NET_VEHICLE_COLOR_WHITE = 1,                # 白色 "White"; white "White";
    NET_VEHICLE_COLOR_BLACK = 2,                # 黑色 "Black"; black "Black";
    NET_VEHICLE_COLOR_RED = 3,                  # 红色 "Red"; red "Red";
    NET_VEHICLE_COLOR_YELLOW = 4,               # 黄色 "Yellow"; yellow "Yellow";
    NET_VEHICLE_COLOR_GRAY = 5,                 # 灰色 "Gray"; gray "Gray";
    NET_VEHICLE_COLOR_BLUE = 6,                 # 蓝色 "Blue"; blue "Blue";
    NET_VEHICLE_COLOR_GREEN = 7,                # 绿色 "Green"; green "Green";
    NET_VEHICLE_COLOR_PINK = 8,                 # 粉红色 "Pink"; pink "Pink";
    NET_VEHICLE_COLOR_PURPLE = 9,               # 紫色 "Purple"; purple "Purple";
    NET_VEHICLE_COLOR_BROWN = 10,               # 棕色 "Brown"; brown "Brown";

class EM_NET_AUTHORITY_TYPE(IntEnum):
    """
    """
    NET_AUTHORITY_UNKNOW = 0,
    NET_AUTHORITY_OPEN_GATE = 1,                # 开闸权限; open gate;

class EM_NET_TRAFFIC_CAR_CONTROL_TYPE(IntEnum):
    """
    布控类型; deployment type
    """
    NET_CAR_CONTROL_OTHER = 0,                  # 其他; Other;
    NET_CAR_CONTROL_OVERDUE_NO_CHECK = 1,       # 过期未检 "OverdueNoCheck"; Overdue inspection "OverdueNoCheck";
    NET_CAR_CONTROL_BRIGANDAGE_CAR = 2,         # 盗抢车辆 "BrigandageCar"; Stolen vehicles "BrigandageCar";
    NET_CAR_CONTROL_BREAKING = 3,               # 违章 "Breaking"; Break rules and regulations "Breaking";
    NET_CAR_CONTROL_CAUSETROUBLE_ESCAPE = 4,    # 
    NET_CAR_CONTROL_CAUSETROUBLE_OVERDUEPARKING = 5,    # 停车欠费 "OverdueParking"; Parking arrears "OverdueParking";
    NET_CAR_CONTROL_COUNTERFEI_PLATE_CAR = 6,   # 假牌车 "CounterfeitPlateCar"; "CounterfeitPlateCar";
    NET_CAR_CONTROL_FAKE_PLATE_CAR = 7,         # 套牌车 "FakePlateCar"; "FakePlateCar";
    NET_CAR_CONTROL_FOCAL_CAR = 8,              # 重点车辆 "FocalCar"; "FocalCar";
    NET_CAR_CONTROL_GUARANTEE_CAR = 9,          # 保障车辆 "GuaranteeCar"; "GuaranteeCar";
    NET_CAR_CONTROL_FOLLOW_CAR = 10,            # 关注车辆 "FollowCar"; "FollowCar";

class CFG_VIDEO_COMPRESSION(IntEnum):
    """
    视频压缩格式; Video compression format
    """
    VIDEO_FORMAT_UNKNOWN = -1,                  # 未知;Unknown;
    VIDEO_FORMAT_MPEG4 = 0,                     # MPEG4; MPEG4;
    VIDEO_FORMAT_MS_MPEG4 = 1,                  # MS-MPEG4; MS-MPEG4;
    VIDEO_FORMAT_MPEG2 = 2,                     # MPEG2; MPEG2;
    VIDEO_FORMAT_MPEG1 = 3,                     # MPEG1; MPEG1;
    VIDEO_FORMAT_H263 = 4,                      # H.263; H.263;
    VIDEO_FORMAT_MJPG = 5,                      # MJPG; MJPG;
    VIDEO_FORMAT_FCC_MPEG4 = 6,                 # FCC-MPEG4; FCC-MPEG4;
    VIDEO_FORMAT_H264 = 7,                      # H.264; H.264;
    VIDEO_FORMAT_H265 = 8,                      # H.265; H.265;
    VIDEO_FORMAT_SVAC = 9,                      # SVAC; SVAC;

class EM_CFG_BITRATE_CONTROL(IntEnum):
    """
    码流控制模式; Bitstream control mode
    """
    BITRATE_CBR = 0,                            # 固定码流; Constant bit rate (CBR);
    BITRATE_VBR = 1,                            # 可变码流; Variable bit rate (VBR);

class EM_CFG_IMAGE_QUALITY(IntEnum):
    """
    画质; Picture quality
    """
    IMAGE_QUALITY_Q10 = 1,                      # 图像质量10%; Image quality 10%;
    IMAGE_QUALITY_Q30 = 2,                      # 图像质量30%; Image quality 30%;
    IMAGE_QUALITY_Q50 = 3,                      # 图像质量50%; Image quality 50%;
    IMAGE_QUALITY_Q60 = 4,                      # 图像质量60%; Image quality 60%;
    IMAGE_QUALITY_Q80 = 5,                      # 图像质量80%; Image quality 80%;
    IMAGE_QUALITY_Q100 = 6,                     # 图像质量100%; Image quality 100%;

class EM_CFG_H264_PROFILE_RANK(IntEnum):
    """
    H264 编码级别; H264 coding level
    """
    PROFILE_BASELINE = 1,                       # 提供I/P帧，仅支持progressive(逐行扫描)和CAVLC; Offer I/P Frame, Only support progressive(Progressive Scan)and CAVLC;
    PROFILE_MAIN = 2,                           # 提供I/P/B帧，支持progressiv和interlaced，提供CAVLC或CABAC; Offer I/P/B Frame, Support progressiv and interlaced, Offer CAVLC or CABAC;
    PROFILE_EXTENDED = 3,                       # 提供I/P/B/SP/SI帧，仅支持progressive(逐行扫描)和CAVLC; Offer I/P/B/SP/SI Frame, Only support progressive(Progressive Scan)and CAVLC;
    PROFILE_HIGH = 4,                           # 即FRExt，Main_Profile基础上新增：8x8 intra prediction(8x8 帧内预测),quant(自定义量化), lossless video coding(无损视频编码), 更多的yuv格式;
                                                # FRExt, Main_Profile Based on the new: 8x8 intra prediction(8x8 Intra-frame Predicdion),Quant( quant ), lossless video coding(lossless video encoding), more yuv format;

class CFG_AUDIO_FORMAT(IntEnum):
    """
    音频格式; Audio format
    """
    AUDIO_FORMAT_G711A = 0,                     # G711a; G711a;
    AUDIO_FORMAT_PCM = 1,                       # PCM; PCM;
    AUDIO_FORMAT_G711U = 2,                     # G711u; G711u;
    AUDIO_FORMAT_AMR = 3,                       # AMR; AMR;
    AUDIO_FORMAT_AAC = 4,                       # AAC; AAC;

class EM_RAID_SYNC_STATE(IntEnum):
    """
    Raid同步状态; Raid synchronization status
    """
    EM_RAID_SYNC_STATE_UNKNOWN = -1,            # 未知; unknown;
    EM_RAID_SYNC_STATE_SELFADAPTION = 0,        # 自适应(默认值); Self-Adaption;
    EM_RAID_SYNC_STATE_SYNCPRIORITY = 1,        # 同步优先，I/O优先分给Raid同步; Sync Priority;
    EM_RAID_SYNC_STATE_BUSINESSPRIORITY = 2,    # 业务优先，I/O优先分给硬盘写数据; Business Priority;
    EM_RAID_SYNC_STATE_EQUILIBRIUM = 3,         # 均衡; Equilibrium;

class EM_ATM_TRADE_TYPE(IntEnum):
    """
    ATM交易类型; ATM transaction type
    """
    ATM_TRADE_ALL = 0,                          # 所有类型; all types;
    ATM_TRADE_ENQUIRY = 1,                      # 查询; search;
    ATM_TRADE_WITHDRAW = 2,                     # 取款; withdraw;
    ATM_TRADE_MODIFY_PASSWORD = 3,              # 修改密码; change password;
    ATM_TRADE_TRANSFER = 4,                     # 转账; transfer;
    ATM_TRADE_DEPOSIT = 5,                      # 存款; deposit;
    ATM_TRADE_CARDLESS_ENQUIRY = 6,             # 无卡查询; search without card;
    ATM_TRADE_CARDLESS_DEPOSIT = 7,             # 无卡存款; deposit without card;
    ATM_TRADE_OTHER = 8,                        # 其他; other;

class EM_RESULT_ORDER_TYPE(IntEnum):
    """
    查询结果排序方式; Sorting method of query results
    """
    EM_RESULT_ORDER_UNKNOWN = 0,                # 未知; unknown order type;
    EM_RESULT_ORDER_ASCENT_BYTIME = 1,          # 按时间升序排序; ascent by time;
    EM_RESULT_ORDER_DESCENT_BYTIME = 2,         # 按时间降序排序; descent by time;

class NET_EM_COMBINATION_MODE(IntEnum):
    """
    是否合并录像; Merge videos
    """
    EM_COMBINATION_MODE_DEFAULT = 0,            # 默认为合并; Default(yes);
    EM_COMBINATION_MODE_YES = 1,                # 合并; yes;
    EM_COMBINATION_MODE_NO = 2,                 # 不合并; no;

class EM_VIDEO_FILE_STATE(IntEnum):
    """
    录像文件的状态; Status of video files
    """
    EM_VIDEO_FILE_STATE_UNKNOWN = 0,            # 未知; unknown;
    EM_VIDEO_FILE_STATE_TEMPORARY = 1,          # 正在写; in wriiting;
    EM_VIDEO_FILE_STATE_COMPLETE = 2,           # 已写完并正常关闭文件句柄; Finished writing and closed file handle normally;

class EM_VIDEO_FILE_TYPE(IntEnum):
    """
    录像文件类型 ; Video file type
    """
    EM_VIDEO_FILE_TYPE_ALL = 0,                 # 所有录像文件 pchCardid=NULL; all video file, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_ALARM_EX = 1,            # 外部报警 pchCardid=NULL; External alarm, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_MONITOR_ALARM = 2,       # 动态检测报警, pchCardid=NULL; Dynamic monitoring alarm, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_ALARM_ALL = 3,           # 所有报警, pchCardid=NULL; ALL Alarm, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_CARD_GET = 4,            # 卡号查询, pchCardid是卡号; card query, pchCardid is card number
    EM_VIDEO_FILE_TYPE_COMBINED_GET = 5,        # 组合条件查询, pchCardid是卡号&&交易类型&& 交易金额(如希望跳过某字段，则相应位置为空); Combined condition query, pchCardid is the card number & & transaction type & & transaction amount (if you want to skip a field, the corresponding position is blank)
    EM_VIDEO_FILE_TYPE_RECORD_OFFSET = 6,       # 录像位置与偏移量长度, pchCardid=NULL; Recording position and offset length, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_CARD_NUMBER_GET = 8,     # 按卡号查询图片(目前仅HB-U和NVS特殊型号的设备支持), pchCardid是卡号; Query pictures by card number (currently only supported by hb-u and NVS special models), pchCardid is card number
    EM_VIDEO_FILE_TYPE_PICTURE_GET = 9,         # 查询图片(目前仅HB-U和NVS特殊型号的设备支持), pchCardid=NULL; Query picture (currently only supported by hb-u and NVS special models), pchCardid=NULL
    EM_VIDEO_FILE_TYPE_FIELD_GET = 10,          # 按字段查询, pchCardid是FELD1&&FELD2&&FELD3&&(如希望跳过某字段，则相应位置为空); Query by field, pchCardid is FELD1&&FELD2&&FELD3&&(if you want to skip a field, the corresponding position is empty)
    EM_VIDEO_FILE_TYPE_NETWORK_DATA = 15,       # 返回网络数据结构, pchCardid=NULL; Return to network data structure, pchCardid=NULL
    EM_VIDEO_FILE_TYPE_TRANSPARENT_DATA = 16,   # 查询所有透明串数据录像文件, pchCardid=NULL; Query all transparent string data video files, pchCardid=NULL

class CFG_ENUM_NET_TRANSMISSION_MODE(IntEnum):
    """
    网络传输模式; Network transmission mode
    """
    CFG_ENUM_NET_MODE_ADAPT = 0,                # 自适应; adapt;
    CFG_ENUM_NET_MODE_HALF10M = 1,              # 10M半双工; half 10M;
    CFG_ENUM_NET_MODE_FULL10M = 2,              # 10M全双工; full 10M;
    CFG_ENUM_NET_MODE_HALF100M = 3,             # 100M半双工; half 100M;
    CFG_ENUM_NET_MODE_FULL100M = 4,             # 100M全双工; full 100M;

class CFG_ENUM_NET_INTERFACE_TYPE(IntEnum):
    """
    网口类型; Network port type
    """
    CFG_ENUM_NET_INTERFACE_TYPE_UNKNOWN = 0,    # 未知; unknown;
    CFG_ENUM_NET_INTERFACE_TYPE_STANDARD = 1,   # 标准网口; standard;
    CFG_ENUM_NET_INTERFACE_TYPE_MANAGER = 2,    # 管理网口; manager;
    CFG_ENUM_NET_INTERFACE_TYPE_EXTEND = 3,     # 扩展网口; extend;

class CFG_THREE_STATUS_BOOL(IntEnum):
    """
    三态布尔类型; Tristate boolean type
    """
    CFG_BOOL_STATUS_UNKNOWN = -1,               # 未知;
    CFG_BOOL_STATUS_FALSE = 0,
    CFG_BOOL_STATUS_TRUE = 1,

class CFG_ENUM_NET_BOND_MODE(IntEnum):
    """
    网络传输模式; Network transmission mode
    """
    CFG_ENUM_NET_BOND_MODE_UNKNOWN = 0,         # 未知; unknown;
    CFG_ENUM_NET_BOND_MODE_BALANCERR = 1,       # RoundRobin负载均衡(为二代负载均衡对应值); RoundRobin load balancing (corresponding value for second-generation load balancing);
    CFG_ENUM_NET_BOND_MODE_BALANCEXOR = 2,      # XOR负载均衡; XOR load balancing;
    CFG_ENUM_NET_BOND_MODE_BALANCETLB = 3,      # 自适应传输负载均衡; Adaptive transmission load balancing;
    CFG_ENUM_NET_BOND_MODE_BALANCEALB = 4,      # 网卡虚拟化负载均衡; Network card virtualization load balancing;
    CFG_ENUM_NET_BOND_MODE_ACTIVEBACKUP = 5,    # 主备模式(由于历史版本原因，设备以此值为容错模式，兼容性考虑，实现中作容错模式用); Active/standby mode (due to historical version reasons, the device uses this value as a fault-tolerant mode, compatibility considerations, use as fault-tolerant mode in implementation);
    CFG_ENUM_NET_BOND_MODE_BROADCAST = 6,       # 容错模式(为保持兼容性，此值无法使用); Fault tolerance mode (to maintain compatibility, this value cannot be used);
    CFG_ENUM_NET_BOND_MODE_802_3AD = 7,         # 动态链路聚合; Dynamic link aggregation;
    CFG_ENUM_NET_BOND_MODE_BRIDGE = 8,          # 网桥((二层交换机，借用bond的格式); Bridge ((Layer 2 switch, borrow the format of bond);

class CFG_ENUM_NET_BOND_LACP(IntEnum):
    """
    802.3ad链路聚合控制方式; 802.3ad link aggregation control mode
    """
    CFG_ENUM_NET_BOND_LACP_UNKNOWN = 0,         # 未知; unknown;
    CFG_ENUM_NET_BOND_LACP_MAC = 1,             # 基于MAC地址; Based on MAC address;
    CFG_ENUM_NET_BOND_LACP_IPPORT = 2,          # 基于IP地址和端口; Based on IP address and port;
    CFG_ENUM_NET_BOND_LACP_IPMAC = 3,           # 基于IP地址和MAC地址; Based on IP address and MAC address;
    CFG_ENUM_NET_BOND_LACP_IP = 4,              # 基于IP地址; ased on IP address;
    CFG_ENUM_NET_BOND_LACP_PORT = 5,            # 基于端口; ased on Port;

class EM_HUMAN_TEMPERATURE_STATUS(IntEnum):
    """
    人体测温状态
    Human body temperature status
    """
    EM_HUMAN_TEMPERATURE_STATUS_UNKNOWN = -1,   # 未知;Unknown;
    EM_HUMAN_TEMPERATURE_STATUS_LOW = 0,        # 
    EM_HUMAN_TEMPERATURE_STATUS_NORMAL = 1,     # 正常;Normal temperature;
    EM_HUMAN_TEMPERATURE_STATUS_HIGH = 2,       # 

class EM_FACE_CHECK(IntEnum):
    """
    刷卡开门时，门禁后台校验人脸是否是同一个人
    When swiping the card to open the door, the access control background checks whether the face is the same person
    """
    EM_FACE_CHECK_UNKNOWN = -1,                 # 未知;Unknown;
    EM_FACE_CHECK_NODATA = 0,                   # 该人员无人脸数据;The person has no face data;
    EM_FACE_CHECK_CONSISTENT = 1,               # 刷卡和人脸人员一致;Swiping card is consistent with face personnel;
    EM_FACE_CHECK_NOT_CONSISTENT = 2,           # 刷卡和人脸人员不一致;Card swiping and face personnel are inconsistent;

class EM_QRCODE_IS_EXPIRED(IntEnum):
    """
    二维码是否过期
    Is the QR code expired
    """
    EM_QRCODE_EXPIRED_UNKNOWN = 0,              # 未知;Unknown;
    EM_QRCODE_NO_EXPIRED = 1,                   # 未过期;Not expired;
    EM_QRCODE_EXPIRED = 2,                      # 过期;Expired;

class EM_QRCODE_STATE(IntEnum):
    """
    二维码状态
    QR code status
    """
    EM_QRCODE_STATE_UNKNOWN = 0,                # 未知;Unknown;
    EM_QRCODE_STATE_CLEARED = 1,                # 已批准;Approved;
    EM_QRCODE_STATE_NOCLEARED = 2,              # 未批准;Not Approved;

class EM_TEST_ITEMS(IntEnum):
    """
    测试项目
    Test items
    """
    EM_TEST_ITEMS_UNKNOWN = -1,                 # 未知;UNKNOWN;
    EM_TEST_ITEMS_OTHER = 0,                    # 其他项目;other projects;
    EM_TEST_ITEMS_HAND_TEST = 1,                # 手部测试静电电阻;Hand test electrostatic resistance;
    EM_TEST_ITEMS_TWOFEET_TEST = 2,             # 双脚测试静电电阻;Two feet test electrostatic resistance;
    EM_TEST_ITEMS_HANDTWOFEET_TEST = 3,         # 手部和双脚测试静电电阻;Test electrostatic resistance with hands and feet;
    EM_TEST_ITEMS_NONE = 4,                     # 全部不测;All untested;

class EM_ESD_RESULT(IntEnum):
    """
    测试结果
    Test Result
    """
    EM_ESD_RESULT_UNKNOWN = -1,                 # 未知;UNKNOWN;
    EM_ESD_RESULT_OTHER_ABERRANT = 0,           # 其他异常;Other abnormalities;
    EM_ESD_RESULT_TEST_PASS = 1,                # 测试通过;Test passed;
    EM_ESD_RESULT_HAND_TEST_FAIL = 2,           # 手测试未通过;Hand test failed;
    EM_ESD_RESULT_LEFTFOOT_TEST_FAIL = 3,       # 左脚测试未通过;Left foot test failed;
    EM_ESD_RESULT_RIGHTFOOT_TEST_FAIL = 4,      # 右脚测试未通过;The right foot test failed;
    EM_ESD_RESULT_FOOT_TEST_FAIL = 5,           # 双脚测试未通过;The foot test failed;
    EM_ESD_RESULT_TEST_FAIL = 6,                # 全部测试未通过;All tests failed;

class EM_TRAVEL_CODE_COLOR(IntEnum):
    """
    行程码状态
    Trip code status
    """
    EM_TRAVEL_CODE_COLOR_UNKNOWN = 0,           # 未知;Unknown;
    EM_TRAVEL_CODE_COLOR_RED = 1,               # 红;Red;
    EM_TRAVEL_CODE_COLOR_GREEN = 2,             # 绿;Green;
    EM_TRAVEL_CODE_COLOR_YELLOW = 3,            # 黄;Yellow;
    EM_TRAVEL_CODE_COLOR_ORANGE = 4,            # 橙;Orange;

class EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD(IntEnum):
    """
    门禁出入记录排序字段
    Order field of entrance guard access records
    """
    EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_UNKNOWN = 0,    # 未知;unknown;
    EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_RECNO = 1,    # 记录集编号;Record No.;
    EM_RECORD_ACCESSCTLCARDREC_ORDER_FIELD_CREATETIME = 2,    # 创建时间;Create time;

class EM_RECORD_ORDER_TYPE(IntEnum):
    """
    排序类型
    Order type
    """
    EM_RECORD_ORDER_TYPE_UNKNOWN = 0,           # 未知;unknown;
    EM_RECORD_ORDER_TYPE_ASCENT = 1,            # 升序;ascent;
    EM_RECORD_ORDER_TYPE_DESCENT = 2,           # 降序;descent;

class EM_NET_ENUM_DIRECTION_ACCESS_CTL(IntEnum):
    """
    开门方向
    Access Control open door Direction
    """
    NET_ENUM_DIRECTION_UNKNOWN = 0,
    NET_ENUM_DIRECTION_ENTRY = 1,               # 进门;entry;
    NET_ENUM_DIRECTION_EXIT = 2,                # 出门;exit;

class EM_CITIZENIDCARD_SEX_TYPE(IntEnum):
    """
    性别
    Citizen sex type
    """
    EM_CITIZENIDCARD_SEX_TYPE_UNKNOWN = 0,      # 未知;Unknown;
    EM_CITIZENIDCARD_SEX_TYPE_MALE = 1,         # 男;Male;
    EM_CITIZENIDCARD_SEX_TYPE_FEMALE = 2,       # 女;Female;
    EM_CITIZENIDCARD_SEX_TYPE_UNTOLD = 3,       # 未说明;Untold;

class EM_CITIZENIDCARD_EC_TYPE(IntEnum):
    """
    民族
    EC
    """
    EM_CITIZENIDCARD_EC_Unknown = 0,            # 未知;Known;
    EM_CITIZENIDCARD_EC_Han = 1,                # 汉族;Han;
    EM_CITIZENIDCARD_EC_Mongolian = 2,          # 蒙古族;Mongolian;
    EM_CITIZENIDCARD_EC_Hui = 3,                # 回族;Hui;
    EM_CITIZENIDCARD_EC_Tibetan = 4,            # 藏族;Tibetan;
    EM_CITIZENIDCARD_EC_Uygur = 5,              # 维吾尔族;Uygur;
    EM_CITIZENIDCARD_EC_Miao = 6,               # 苗族;Miao;
    EM_CITIZENIDCARD_EC_Yi = 7,                 # 彝族;Yi;
    EM_CITIZENIDCARD_EC_Zhuang = 8,             # 壮族;Zhuang;
    EM_CITIZENIDCARD_EC_Bouyei = 9,             # 布依族;Bouyei;
    EM_CITIZENIDCARD_EC_Korean = 10,            # 朝鲜族;Korean;
    EM_CITIZENIDCARD_EC_Manchu = 11,            # 满族;Manchu;
    EM_CITIZENIDCARD_EC_Dong = 12,              # 侗族;Dong;
    EM_CITIZENIDCARD_EC_Yao = 13,               # 瑶族;Yao;
    EM_CITIZENIDCARD_EC_Bai = 14,               # 白族;Bai;
    EM_CITIZENIDCARD_EC_Tujia = 15,             # 土家族;Tujia;
    EM_CITIZENIDCARD_EC_Hani = 16,              # 哈尼族;Hani;
    EM_CITIZENIDCARD_EC_Kazak = 17,             # 哈萨克族;Kazak;
    EM_CITIZENIDCARD_EC_Dai = 18,               # 傣族;Dai;
    EM_CITIZENIDCARD_EC_Li = 19,                # 黎族;Li;
    EM_CITIZENIDCARD_EC_Lisu = 20,              # 傈僳族;Lisu;
    EM_CITIZENIDCARD_EC_Va = 21,                # 佤族;Va;
    EM_CITIZENIDCARD_EC_She = 22,               # 畲族;She;
    EM_CITIZENIDCARD_EC_Gaoshan = 23,           # 高山族;Gaoshan;
    EM_CITIZENIDCARD_EC_Lahu = 24,              # 拉祜族;Lahu;
    EM_CITIZENIDCARD_EC_Shui = 25,              # 水族;Shui;
    EM_CITIZENIDCARD_EC_Dongxiang = 26,         # 东乡族;Dongxiang;
    EM_CITIZENIDCARD_EC_Naxi = 27,              # 纳西族;Naxi;
    EM_CITIZENIDCARD_EC_Jingpo = 28,            # 景颇族;Jingpo;
    EM_CITIZENIDCARD_EC_Kirgiz = 29,            # 柯尔克孜族;Kirgiz;
    EM_CITIZENIDCARD_EC_Tu = 30,                # 土族;Tu;
    EM_CITIZENIDCARD_EC_Daur = 31,              # 达斡尔族;Daur;
    EM_CITIZENIDCARD_EC_Mulam = 32,             # 仫佬族;Mulam;
    EM_CITIZENIDCARD_EC_Qoiang = 33,            # 羌族;Qoiang;
    EM_CITIZENIDCARD_EC_Blang = 34,             # 布朗族;Blang;
    EM_CITIZENIDCARD_EC_Salar = 35,             # 撒拉族;Salar;
    EM_CITIZENIDCARD_EC_Maonan = 36,            # 毛南族;Maonan;
    EM_CITIZENIDCARD_EC_Gelo = 37,              # 仡佬族;Gelo;
    EM_CITIZENIDCARD_EC_Xibe = 38,              # 锡伯族;Xibe;
    EM_CITIZENIDCARD_EC_Achang = 39,            # 阿昌族;Achang;
    EM_CITIZENIDCARD_EC_Pumi = 40,              # 普米族;Pumi;
    EM_CITIZENIDCARD_EC_Tajik = 41,             # 塔吉克族;Tajik;
    EM_CITIZENIDCARD_EC_Nu = 42,                # 怒族;Nu;
    EM_CITIZENIDCARD_EC_Ozbek = 43,             # 乌孜别克族;Ozbek;
    EM_CITIZENIDCARD_EC_Russian = 44,           # 俄罗斯族;Russian;
    EM_CITIZENIDCARD_EC_Ewenkl = 45,            # 鄂温克族;Ewenkl;
    EM_CITIZENIDCARD_EC_Deang = 46,             # 德昂族;Deang;
    EM_CITIZENIDCARD_EC_Bonan = 47,             # 保安族;Bonan;
    EM_CITIZENIDCARD_EC_Yugur = 48,             # 裕固族;Yugur;
    EM_CITIZENIDCARD_EC_Jing = 49,              # 京族;Jing;
    EM_CITIZENIDCARD_EC_Tatar = 50,             # 塔塔尔族;Tatar;
    EM_CITIZENIDCARD_EC_Drung = 51,             # 独龙族;Drung;
    EM_CITIZENIDCARD_EC_Oroqen = 52,            # 鄂伦春族;Oroqen;
    EM_CITIZENIDCARD_EC_Hezhen = 53,            # 赫哲族;Hezhen;
    EM_CITIZENIDCARD_EC_Moinba = 54,            # 门巴族;Moinba;
    EM_CITIZENIDCARD_EC_Lhoba = 55,             # 珞巴族;Lhoba;
    EM_CITIZENIDCARD_EC_Jino = 56,              # 基诺族;Jino;

class EM_TEMPERATURE_UNIT(IntEnum):
    """
    温度单位
    temperature unit
    """
    EM_TEMPERATURE_UNKNOWN = -1,                # 未知;unknown;
    EM_TEMPERATURE_CENTIGRADE = 0,              # 摄氏度;centigrade;
    EM_TEMPERATURE_FAHRENHEIT = 1,              # 华氏度;fahrenheit;
    EM_TEMPERATURE_KELVIN = 2,                  # 开尔文;kelvin;

class EM_TOLLS_VEHICLE_TYPE(IntEnum):
    """
    收费公路车辆通行费车型分类
    Classification of toll road vehicle types
    """
    EM_TOLLS_VEHICLE_TYPE_UNKNOWN = 0,          # 未知;Unknown;
    EM_TOLLS_VEHICLE_TYPE_PASSENGER_CAR1 = 1,   # 一型客车;Passenger car 1;
    EM_TOLLS_VEHICLE_TYPE_PASSENGER_CAR2 = 2,   # 二型客车;Passenger car 2;
    EM_TOLLS_VEHICLE_TYPE_PASSENGER_CAR3 = 3,   # 三型客车;Passenger car 3;
    EM_TOLLS_VEHICLE_TYPE_PASSENGER_CAR4 = 4,   # 四型客车;Passenger car 4;
    EM_TOLLS_VEHICLE_TYPE_TRUCK1 = 11,          # 一型货车;truck 1;
    EM_TOLLS_VEHICLE_TYPE_TRUCK2 = 12,          # 二型货车;truck 2;
    EM_TOLLS_VEHICLE_TYPE_TRUCK3 = 13,          # 三型货车;truck 3;
    EM_TOLLS_VEHICLE_TYPE_TRUCK4 = 14,          # 四型货车;truck 4;
    EM_TOLLS_VEHICLE_TYPE_TRUCK5 = 15,          # 五型货车;truck 5;
    EM_TOLLS_VEHICLE_TYPE_TRUCK6 = 16,          # 六型货车;truck 6;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE1 = 21,    # 一型专项作业车;Operation vehicle 1;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE2 = 22,    # 二型专项作业车;Operation vehicle 2;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE3 = 23,    # 三型专项作业车;Operation vehicle 3;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE4 = 24,    # 四型专项作业车;Operation vehicle 4;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE5 = 25,    # 五型专项作业车;Operation vehicle 5;
    EM_TOLLS_VEHICLE_TYPE_OPERATION_VEHICLE6 = 26,    # 六型专项作业车;Operation vehicle 6;

class EM_MSG_OBJ_PERSON_DIRECTION(IntEnum):
    """
    入侵方向
    intrusion direction
    """
    EM_MSG_OBJ_PERSON_DIRECTION_UNKOWN = 0,     # 未知方向;unknown direction;
    EM_MSG_OBJ_PERSON_DIRECTION_LEFT_TO_RIGHT = 1,    # 从左向右;from left to right;
    EM_MSG_OBJ_PERSON_DIRECTION_RIGHT_TO_LEFT = 2,    # 从右向左;from right ro left;

class EM_CAR_TYPE(IntEnum):
    """
    车辆类型
    the type of the car
    """
    EM_CAR_0 = 0,                               # 其他车辆;
    EM_CAR_1 = 1,                               # 大型普通客车;
    EM_CAR_2 = 2,                               # 大型双层客车;
    EM_CAR_3 = 3,                               # 大型卧铺客车;
    EM_CAR_4 = 4,                               # 大型铰接客车;
    EM_CAR_5 = 5,                               # 大型越野客车;
    EM_CAR_6 = 6,                               # 大型轿车;
    EM_CAR_7 = 7,                               # 大型专用客车;
    EM_CAR_8 = 8,                               # 大型专用校车;
    EM_CAR_9 = 9,                               # 中型普通客车;
    EM_CAR_10 = 10,                             # 中型双层客车;
    EM_CAR_11 = 11,                             # 中型卧铺客车;
    EM_CAR_12 = 12,                             # 中型铰接客车;
    EM_CAR_13 = 13,                             # 中型越野客车;
    EM_CAR_14 = 14,                             # 中型轿车;
    EM_CAR_15 = 15,                             # 中型专用客车;
    EM_CAR_16 = 16,                             # 中型专用校车;
    EM_CAR_17 = 17,                             # 小型普通客车;
    EM_CAR_18 = 18,                             # 小型越野客车;
    EM_CAR_19 = 19,                             # 小型轿车;
    EM_CAR_20 = 20,                             # 小型专用客车;
    EM_CAR_21 = 21,                             # 小型专用校车;
    EM_CAR_22 = 22,                             # 小型面包车;
    EM_CAR_23 = 23,                             # 微型普通客车;
    EM_CAR_24 = 24,                             # 微型越野客车;
    EM_CAR_25 = 25,                             # 微型轿车;
    EM_CAR_26 = 26,                             # 微型面包车;
    EM_CAR_27 = 27,                             # 重型半挂牵引车;
    EM_CAR_28 = 28,                             # 重型全挂牵引车;
    EM_CAR_29 = 29,                             # 中型半挂牵引车;
    EM_CAR_30 = 30,                             # 中型全挂牵引车;
    EM_CAR_31 = 31,                             # 轻型半挂牵引车;
    EM_CAR_32 = 32,                             # 轻型全挂牵引车;
    EM_CAR_33 = 33,                             # 大型非载货专项作业车;
    EM_CAR_34 = 34,                             # 大型载货专项作业车;
    EM_CAR_35 = 35,                             # 中型非载货专项作业车;
    EM_CAR_36 = 36,                             # 中型载货专项作业车;
    EM_CAR_37 = 37,                             # 小型非载货专项作业车;
    EM_CAR_38 = 38,                             # 小型载货专项作业车;
    EM_CAR_39 = 39,                             # 微型非载货专项作业车;
    EM_CAR_40 = 40,                             # 微型载货专项作业车;
    EM_CAR_41 = 41,                             # 重型非载货专项作业车;
    EM_CAR_42 = 42,                             # 重型载货专项作业车;
    EM_CAR_43 = 43,                             # 轻型非载货专项作业车;
    EM_CAR_44 = 44,                             # 轻型载货专项作业车;
    EM_CAR_45 = 45,                             # 普通正三轮摩托车;
    EM_CAR_46 = 46,                             # 轻便正三轮摩托车;
    EM_CAR_47 = 47,                             # 正三轮载客摩托车;
    EM_CAR_48 = 48,                             # 正三轮载货摩托车;
    EM_CAR_49 = 49,                             # 侧三轮摩托车;
    EM_CAR_50 = 50,                             # 普通二轮摩托车;
    EM_CAR_51 = 51,                             # 轻便二轮摩托车;
    EM_CAR_52 = 52,                             # 无轨电车;
    EM_CAR_53 = 53,                             # 有轨电车;
    EM_CAR_54 = 54,                             # 三轮汽车;
    EM_CAR_55 = 55,                             # 轮式装载机械;
    EM_CAR_56 = 56,                             # 轮式挖掘机械;
    EM_CAR_57 = 57,                             # 轮式平地机械;
    EM_CAR_58 = 58,                             # 重型普通货车;
    EM_CAR_59 = 59,                             # 重型厢式货车;
    EM_CAR_60 = 60,                             # 重型封闭货车;
    EM_CAR_61 = 61,                             # 重型罐式货车;
    EM_CAR_62 = 62,                             # 重型平板货车;
    EM_CAR_63 = 63,                             # 重型集装箱车;
    EM_CAR_64 = 64,                             # 重型自卸货车;
    EM_CAR_65 = 65,                             # 重型特殊结构货车;
    EM_CAR_66 = 66,                             # 重型仓栅式货车;
    EM_CAR_67 = 67,                             # 重型车辆运输车;
    EM_CAR_68 = 68,                             # 重型厢式自卸货车;
    EM_CAR_69 = 69,                             # 重型罐式自卸货车;
    EM_CAR_70 = 70,                             # 重型平板自卸货车;
    EM_CAR_71 = 71,                             # 重型集装箱自卸货车;
    EM_CAR_72 = 72,                             # 重型特殊结构自卸货车;
    EM_CAR_73 = 73,                             # 重型仓栅式自卸货车;
    EM_CAR_74 = 74,                             # 中型普通货车;
    EM_CAR_75 = 75,                             # 中型厢式货车;
    EM_CAR_76 = 76,                             # 中型封闭货车;
    EM_CAR_77 = 77,                             # 中型罐式货车;
    EM_CAR_78 = 78,                             # 中型平板货车;
    EM_CAR_79 = 79,                             # 中型集装箱车;
    EM_CAR_80 = 80,                             # 中型自卸货车;
    EM_CAR_81 = 81,                             # 中型特殊结构货车;
    EM_CAR_82 = 82,                             # 中型仓栅式货车;
    EM_CAR_83 = 83,                             # 中型车辆运输车;
    EM_CAR_84 = 84,                             # 中型厢式自卸货车;
    EM_CAR_85 = 85,                             # 中型罐式自卸货车;
    EM_CAR_86 = 86,                             # 中型平板自卸货车;
    EM_CAR_87 = 87,                             # 中型集装箱自卸货车;
    EM_CAR_88 = 88,                             # 中型特殊结构自卸货车;
    EM_CAR_89 = 89,                             # 中型仓栅式自卸货车;
    EM_CAR_90 = 90,                             # 轻型普通货车;
    EM_CAR_91 = 91,                             # 轻型厢式货车;
    EM_CAR_92 = 92,                             # 轻型封闭货车;
    EM_CAR_93 = 93,                             # 轻型罐式货车;
    EM_CAR_94 = 94,                             # 轻型平板货车;
    EM_CAR_95 = 95,                             # 轻型自卸货车;
    EM_CAR_96 = 96,                             # 轻型特殊结构货车;
    EM_CAR_97 = 97,                             # 轻型仓栅式货车;
    EM_CAR_98 = 98,                             # 轻型车辆运输车;
    EM_CAR_99 = 99,                             # 轻型厢式自卸货车;
    EM_CAR_100 = 100,                           # 轻型罐式自卸货车;
    EM_CAR_101 = 101,                           # 轻型平板自卸货车;
    EM_CAR_102 = 102,                           # 轻型特殊结构自卸货车;
    EM_CAR_103 = 103,                           # 轻型仓栅式自卸货车;
    EM_CAR_104 = 104,                           # 微型普通货车;
    EM_CAR_105 = 105,                           # 微型厢式货车;
    EM_CAR_106 = 106,                           # 微型封闭货车;
    EM_CAR_107 = 107,                           # 微型罐式货车;
    EM_CAR_108 = 108,                           # 微型自卸货车;
    EM_CAR_109 = 109,                           # 微型特殊结构货车;
    EM_CAR_110 = 110,                           # 微型仓栅式货车;
    EM_CAR_111 = 111,                           # 微型车辆运输车;
    EM_CAR_112 = 112,                           # 微型厢式自卸货车;
    EM_CAR_113 = 113,                           # 微型罐式自卸货车;
    EM_CAR_114 = 114,                           # 微型特殊结构自卸货车;
    EM_CAR_115 = 115,                           # 微型仓栅式自卸货车;
    EM_CAR_116 = 116,                           # 普通低速货车;
    EM_CAR_117 = 117,                           # 厢式低速货车;
    EM_CAR_118 = 118,                           # 罐式低速货车;
    EM_CAR_119 = 119,                           # 自卸低速货车;
    EM_CAR_120 = 120,                           # 仓栅式低速货车;
    EM_CAR_121 = 121,                           # 厢式自卸低速货车;
    EM_CAR_122 = 122,                           # 罐式自卸低速货车;
    EM_CAR_123 = 123,                           # 重型普通全挂车;
    EM_CAR_124 = 124,                           # 重型厢式全挂车;
    EM_CAR_125 = 125,                           # 重型罐式全挂车;
    EM_CAR_126 = 126,                           # 重型平板全挂车;
    EM_CAR_127 = 127,                           # 重型集装箱全挂车;
    EM_CAR_128 = 128,                           # 重型自卸全挂车;
    EM_CAR_129 = 129,                           # 重型仓栅式全挂车;
    EM_CAR_130 = 130,                           # 重型旅居全挂车;
    EM_CAR_131 = 131,                           # 重型专项作业全挂车;
    EM_CAR_132 = 132,                           # 重型厢式自卸全挂车;
    EM_CAR_133 = 133,                           # 重型罐式自卸全挂车;
    EM_CAR_134 = 134,                           # 重型平板自卸全挂车;
    EM_CAR_135 = 135,                           # 重型集装箱自卸全挂车;
    EM_CAR_136 = 136,                           # 重型仓栅式自卸全挂车;
    EM_CAR_137 = 137,                           # 重型专项作业自卸全挂车;
    EM_CAR_138 = 138,                           # 中型普通全挂车;
    EM_CAR_139 = 139,                           # 中型厢式全挂车;
    EM_CAR_140 = 140,                           # 中型罐式全挂车;
    EM_CAR_141 = 141,                           # 中型平板全挂车;
    EM_CAR_142 = 142,                           # 中型集装箱全挂车;
    EM_CAR_143 = 143,                           # 中型自卸全挂车;
    EM_CAR_144 = 144,                           # 中型仓栅式全挂车;
    EM_CAR_145 = 145,                           # 中型旅居全挂车;
    EM_CAR_146 = 146,                           # 中型专项作业全挂车;
    EM_CAR_147 = 147,                           # 中型厢式自卸全挂车;
    EM_CAR_148 = 148,                           # 中型罐式自卸全挂车;
    EM_CAR_149 = 149,                           # 中型平板自卸全挂车;
    EM_CAR_150 = 150,                           # 中型集装箱自卸全挂车;
    EM_CAR_151 = 151,                           # 中型仓栅式自卸全挂车;
    EM_CAR_152 = 152,                           # 中型专项作业自卸全挂车;
    EM_CAR_153 = 153,                           # 轻型普通全挂车;
    EM_CAR_154 = 154,                           # 轻型厢式全挂车;
    EM_CAR_155 = 155,                           # 轻型罐式全挂车;
    EM_CAR_156 = 156,                           # 轻型平板全挂车;
    EM_CAR_157 = 157,                           # 轻型自卸全挂车;
    EM_CAR_158 = 158,                           # 轻型仓栅式全挂车;
    EM_CAR_159 = 159,                           # 轻型旅居全挂车;
    EM_CAR_160 = 160,                           # 轻型专项作业全挂车;
    EM_CAR_161 = 161,                           # 轻型厢式自卸全挂车;
    EM_CAR_162 = 162,                           # 轻型罐式自卸全挂车;
    EM_CAR_163 = 163,                           # 轻型平板自卸全挂车;
    EM_CAR_164 = 164,                           # 轻型集装箱自卸全挂车;
    EM_CAR_165 = 165,                           # 轻型仓栅式自卸全挂车;
    EM_CAR_166 = 166,                           # 轻型专项作业自卸全挂车;
    EM_CAR_167 = 167,                           # 重型普通半挂车;
    EM_CAR_168 = 168,                           # 重型厢式半挂车;
    EM_CAR_169 = 169,                           # 重型罐式半挂车;
    EM_CAR_170 = 170,                           # 重型平板半挂车;
    EM_CAR_171 = 171,                           # 重型集装箱半挂车;
    EM_CAR_172 = 172,                           # 重型自卸半挂车;
    EM_CAR_173 = 173,                           # 重型特殊结构半挂车;
    EM_CAR_174 = 174,                           # 重型仓栅式半挂车;
    EM_CAR_175 = 175,                           # 重型旅居半挂车;
    EM_CAR_176 = 176,                           # 重型专项作业半挂车;
    EM_CAR_177 = 177,                           # 重型低平板半挂车;
    EM_CAR_178 = 178,                           # 重型车辆运输半挂车;
    EM_CAR_179 = 179,                           # 重型罐式自卸半挂车;
    EM_CAR_180 = 180,                           # 重型平板自卸半挂车;
    EM_CAR_181 = 181,                           # 重型集装箱自卸半挂车;
    EM_CAR_182 = 182,                           # 重型特殊结构自卸半挂车;
    EM_CAR_183 = 183,                           # 重型仓栅式自卸半挂车;
    EM_CAR_184 = 184,                           # 重型专项作业自卸半挂车;
    EM_CAR_185 = 185,                           # 重型低平板自卸半挂车;
    EM_CAR_186 = 186,                           # 重型中置轴旅居挂车;
    EM_CAR_187 = 187,                           # 重型中置轴车辆运输车;
    EM_CAR_188 = 188,                           # 重型中置轴普通挂车;
    EM_CAR_189 = 189,                           # 中型普通半挂车;
    EM_CAR_190 = 190,                           # 中型厢式半挂车;
    EM_CAR_191 = 191,                           # 中型罐式半挂车;
    EM_CAR_192 = 192,                           # 中型平板半挂车;
    EM_CAR_193 = 193,                           # 中型集装箱半挂车;
    EM_CAR_194 = 194,                           # 中型自卸半挂车;
    EM_CAR_195 = 195,                           # 中型特殊结构半挂车;
    EM_CAR_196 = 196,                           # 中型仓栅式半挂车;
    EM_CAR_197 = 197,                           # 中型旅居半挂车;
    EM_CAR_198 = 198,                           # 中型专项作业半挂车;
    EM_CAR_199 = 199,                           # 中型低平板半挂车;
    EM_CAR_200 = 200,                           # 中型车辆运输半挂车;
    EM_CAR_201 = 201,                           # 中型罐式自卸半挂车;
    EM_CAR_202 = 202,                           # 中型平板自卸半挂车;
    EM_CAR_203 = 203,                           # 中型集装箱自卸半挂车;
    EM_CAR_204 = 204,                           # 中型特殊结构自卸挂车;
    EM_CAR_205 = 205,                           # 中型仓栅式自卸半挂车;
    EM_CAR_206 = 206,                           # 中型专项作业自卸半挂车;
    EM_CAR_207 = 207,                           # 中型低平板自卸半挂车;
    EM_CAR_208 = 208,                           # 中型中置轴旅居挂车;
    EM_CAR_209 = 209,                           # 中型中置轴车辆运输车;
    EM_CAR_210 = 210,                           # 中型中置轴普通挂车;
    EM_CAR_211 = 211,                           # 轻型普通半挂车;
    EM_CAR_212 = 212,                           # 轻型厢式半挂车;
    EM_CAR_213 = 213,                           # 轻型罐式半挂车;
    EM_CAR_214 = 214,                           # 轻型平板半挂车;
    EM_CAR_215 = 215,                           # 轻型自卸半挂车;
    EM_CAR_216 = 216,                           # 轻型仓栅式半挂车;
    EM_CAR_217 = 217,                           # 轻型旅居半挂车;
    EM_CAR_218 = 218,                           # 轻型专项作业半挂车;
    EM_CAR_219 = 219,                           # 轻型低平板半挂车;
    EM_CAR_220 = 220,                           # 轻型车辆运输半挂车;
    EM_CAR_221 = 221,                           # 轻型罐式自卸半挂车;
    EM_CAR_222 = 222,                           # 轻型平板自卸半挂车;
    EM_CAR_223 = 223,                           # 轻型集装箱自卸半挂车;
    EM_CAR_224 = 224,                           # 轻型特殊结构自卸挂车;
    EM_CAR_225 = 225,                           # 轻型仓栅式自卸半挂车;
    EM_CAR_226 = 226,                           # 轻型专项作业自卸半挂车;
    EM_CAR_227 = 227,                           # 轻型低平板自卸半挂车;
    EM_CAR_228 = 228,                           # 轻型中置轴旅居挂车;
    EM_CAR_229 = 229,                           # 轻型中置轴车辆运输车;
    EM_CAR_230 = 230,                           # 轻型中置轴普通挂车;

class EM_AGE_SEG(IntEnum):
    """
    年龄段
    Age segmentation
    """
    EM_AGE_SEG_UNKOWN = 0,                      # 未知;unknow;
    EM_AGE_SEG_BABY = 2,                        # 婴儿;baby;
    EM_AGE_SEG_CHILD = 10,                      # 幼儿;child;
    EM_AGE_SEG_YOUTH = 28,                      # 青年;youth;
    EM_AGE_SEG_MIDDLE = 50,                     # 中年;middle age;
    EM_AGE_SEG_OLD = 60,                        # 老年;old age;

class EM_NEWUPCLOTHES_TYPE(IntEnum):
    """
    新上衣类型
    New up clothes type
    """
    EM_NEWUPCLOTHES_TYPE_UNKNOWN = 0,           # 未知;unknown;
    EM_NEWUPCLOTHES_TYPE_LONG_SLEEVE = 1,       # 长袖;long sleeve;
    EM_NEWUPCLOTHES_TYPE_SHORT_SLEEVE = 2,      # 短袖;long sleeve;
    EM_NEWUPCLOTHES_TYPE_LONGCOAT = 3,          # 长款大衣;long coat;
    EM_NEWUPCLOTHES_TYPE_JACKET_AND_JEANS = 4,  # 夹克及牛仔服;jacket and jeans;
    EM_NEWUPCLOTHES_TYPE_TSHIRT = 5,            # T恤;T-shirt;
    EM_NEWUPCLOTHES_TYPE_SPORTWEAR = 6,         # 运动装;sport wear;
    EM_NEWUPCLOTHES_TYPE_DOWNJACKETS = 7,       # 羽绒服;down jackets;
    EM_NEWUPCLOTHES_TYPE_SHIRT = 8,             # 衬衫;shirt;
    EM_NEWUPCLOTHES_TYPE_DRESS = 9,             # 连衣裙;dirss;
    EM_NEWUPCLOTHES_TYPE_SUIT = 10,             # 西装;suit;
    EM_NEWUPCLOTHES_TYPE_SWEATER = 11,          # 毛衣;sweater;
    EM_NEWUPCLOTHES_TYPE_SLEEVELESS = 12,       # 无袖;sleeveless;
    EM_NEWUPCLOTHES_TYPE_VEST = 13,             # 背心;vest;

class EM_NEWDOWNCLOTHES_TYPE(IntEnum):
    """
    新下衣类型
    New down clothes type
    """
    EM_NEWDOWNCLOTHES_TYPE_UNKNOWN = 0,         # 未知;unknown;
    EM_NEWDOWNCLOTHES_TYPE_TROUSERS = 1,        # 长裤;trousers;
    EM_NEWDOWNCLOTHES_TYPE_SHORTS = 2,          # 短裤;shorts;
    EM_NEWDOWNCLOTHES_TYPE_SKIRT = 3,           # 裙子;skirt;

class EM_VEHICLE_POSTURE_TYPE(IntEnum):
    """
    车辆姿势
    Vehicle posture
    """
    UNKNOWN = 0,                                # 未知;Unknown;
    HEAD = 1,                                   # 车头;Vehicle head;
    SIDE = 2,                                   # 车侧;Vehicle side;
    TAIL = 3,                                   # 车尾;Vehicle tail;

class EM_CAR_DRIVING_DIRECTION(IntEnum):
    """
    规则区内车辆行驶方向
    Driving direction of vehicles in the regular area
    """
    UNKNOWN = 0,                                # 未知;Unknwon;
    DRIVE_IN_AREA = 1,                          # 驶入区域;Drive in area;
    EXIT_AREA = 2,                              # 驶出区域;Exit area;

class EM_IMAGE_TYPE(IntEnum):
    """
    图片类型
    Picture type
    """
    EM_IMAGE_UNKNOWN = -1,                      # 未知;unknown;
    EM_IMAGE_INSPECTOR = 0,                     # 安检员图片;Picture of security inspector;
    EM_IMAGE_PACKAGE = 1,                       # 包裹图片;Package picture;

class EM_IMAGE_TYPE_EX2(IntEnum):
    """
    图片类型
    Picture type
    """
    EM_IMAGE_TYPE_UNKNOWN = 0,                  # 未知;unknown;
    EM_IMAGE_TYPE_SCENE_IMAGE = 1,              # 全景广角度;Panoramic wide angle;
    EM_IMAGE_TYPE_GLOBAL_SCENE = 2,             # 大图;Large picture;
    EM_IMAGE_TYPE_THUM_IMAGE = 3,               # 大图（全景图）的缩略图;Thumbnail of large image (panoramic image);
    EM_IMAGE_TYPE_FACE_SCENE_IMAGE = 4,         # 人脸全景图;Panoramic image of human face;
    EM_IMAGE_TYPE_FACE_IMAGE = 5,               # 人脸图;face image;
    EM_IMAGE_TYPE_HUMAN_IMAGE = 6,              # 人体图;Human body image;
    EM_IMAGE_TYPE_ALONG_WITH_FACE_HUMAN_IMAGE = 7,    # 与最优人脸同画面的人体图;Human body image with the same picture as the optimal face;
    EM_IMAGE_TYPE_ALONG_WITH_FACE_HUMAN_SCENE_IMAGE = 8,    # 与最优人脸同画面人体的全景图;A panoramic view of the human body in the same picture as the optimal face;
    EM_IMAGE_TYPE_PARKING_IMAGE = 9,            # 车位抠图;Parking space cutout;
    EM_IMAGE_TYPE_BINARIZED_PLATE = 10,         # 车身特写抠图;Close-up cutout of car body;
    EM_IMAGE_TYPE_DEPOSIT_IMAGE_INFO = 11,      # 格口抠图;Grid cutout;
    EM_IMAGE_TYPE_IMAGE_INFO = 12,              # 普通图，图片名称未定义情况使用;Normal image, used when the image name is not defined;

class EM_OPEN_STROBE_TYPE(IntEnum):
    """
    开闸类型
    Open strobe type
    """
    EM_OPEN_STROBE_TYPE_UNKNOWN = 0,            # 未知;unknown;
    EM_OPEN_STROBE_TYPE_NORMAL = 1,             # 正常开闸(默认);Normal;
    EM_OPEN_STROBE_TYPE_TEST = 2,               # 测试手动开闸（用于施工前期）;Test;
    EM_OPEN_STROBE_TYPE_MANUAL = 3,             # 手动开闸;Manual;

class EM_DATA_SOURCE_TYPE(IntEnum):
    """
    智能分析数据源类型
    type of analyse data source
    """
    EM_DATA_SOURCE_REMOTE_UNKNOWN = 0,          # 未知;unknown;
    EM_DATA_SOURCE_REMOTE_REALTIME_STREAM = 1,  # 远程实时流 , 对应 NET_REMOTE_REALTIME_STREAM_INFO;remote stream, Corresponding to NET_REMOTE_STREAM_INFO;
    EM_DATA_SOURCE_PUSH_PICFILE = 2,            # 主动推送图片文件, 对应 NET_PUSH_PICFILE_INFO;picture file which is pushed actively, Corresponding to NET_PUSH_PICFILE_INFO;
    EM_DATA_SOURCE_REMOTE_VIDEO_FILE = 3,       # 远程视频文件, 对应 NET_REMOTE_VIDEO_FILE_INFO;remote video file, Corresponding to NET_REMOTE_VIDEO_FILE_INFO;
    EM_DATA_SOURCE_REMOTE_PICTURE_FILE = 4,     # 远程图片文件, 对应 NET_REMOTE_PICTURE_FILE_INFO;remote picture file, Corresponding to NET_REMOTE_PICTURE_FILE_INFO;
    EM_DATA_SOURCE_OFFLINE_VIDEO_FILE = 5,      # 离线视频文件（第三方导入的文件）, 对应 NET_OFFLINE_VIDEO_FILE_INFO;offline video file(Third party imported files), Corresponding to NET_OFFLINE_VIDEO_FILE_INFO;
    EM_DATA_SOURCE_PUSH_PICFILE_BYRULE = 6,     # 主动推送图片文件，添加任务时无规则和图片信息，通过推送图片接口，每张图片中带有不同的规则信息（目前能源场景中使用）, 对应 NET_PUSH_PICFILE_BYRULE_INFO;Push picture file by rule, Corresponding to NET_PUSH_PICFILE_BYRULE_INFO;
    EM_DATA_SOURCE_LOCAL_STREAM = 7,            # 本地实时流, 对应 NET_LOCAL_STREAM_INFO;Local Stream, Corresponding to NET_LOCAL_STREAM_INFO;

class EM_ANALYSE_TASK_START_RULE(IntEnum):
    """
    智能任务启动规则
    start rule of analyse task
    """
    EM_ANALYSE_TASK_START_NOW = 0,              # 立刻启动;start now;
    EM_ANALYSE_TASK_START_LATER = 1,            # 稍候手动启动;start later;

class EM_ANALYSE_STATE(IntEnum):
    """
    分析状态
    analyse task state
    """
    EM_ANALYSE_STATE_UNKNOWN = 0,               # 未知;unknown;
    EM_ANALYSE_STATE_IDLE = 1,                  # 已创建但未运行;idle;
    EM_ANALYSE_STATE_ANALYSING = 2,             # 分析中;analysing;
    EM_ANALYSE_STATE_ANALYSING_WAITPUSH = 3,    # 分析中并等待push数据;analysing and waitting push data;
    EM_ANALYSE_STATE_FINISH = 4,                # 正常完成;finish;
    EM_ANALYSE_STATE_ERROR = 5,                 # 执行异常;error;
    EM_ANALYSE_STATE_REMOVED = 6,               # 被删除;removed;
    EM_ANALYSE_STATE_ROUNDFINISH = 7,           # 完成一轮视频源分析;finish one round;
    EM_ANALYSE_STATE_STARTING = 8,              # 任务开启状态;starting;

class EM_ANALYSE_TASK_ERROR(IntEnum):
    """
    智能分析任务错误码
    analyse task error code
    """
    EM_ANALYSE_TASK_ERROR_UNKNOWN = 1,          # 未知;unknown;
    EM_ANALYSE_TASK_ERROR_INSUFFICIENT_DECODING_CAPABILITY = 2,    # 解码能力不足;insufficient decoding capability;
    EM_ANALYSE_TASK_ERROR_INSUFFICIENT_INTELLIGENCE_CAPABILITY = 3,    # 智能能力不足;insufficient intelligence capability;
    EM_ANALYSE_TASK_ERROR_BITSTREAM_FORMAT_NOT_SUPPORTED = 4,    # 码流格式不支持;format not support;
    EM_ANALYSE_TASK_ERROR_ANALYZER_OFF_LINE = 5,    # 分析器离线;analyzer off line;
    EM_ANALYSE_TASK_ERROR_ANALYZER_ON_LINE = 6, # 分析器上线;analyzer on line;

class EM_SCENE_CLASS_TYPE(IntEnum):
    """
    大类业务方案，内容与EM_SCENE_TYPE一致
    same as EM_SCENE_TYPE
    """
    EM_SCENE_CLASS_UNKNOW = 0,                  # 未知;unknow;
    EM_SCENE_CLASS_NORMAL = 1,                  # "Normal" 普通场景;"Normal";
    EM_SCENE_CLASS_TRAFFIC = 2,                 # "Traffic" 交通场景;"Traffic";
    EM_SCENE_CLASS_TRAFFIC_PATROL = 3,          # "TrafficPatrol" 交通巡视;"TrafficPatrol";
    EM_SCENE_CLASS_FACEDETECTION = 4,           # "FaceDetection" 人脸检测/目标识别;"FaceDetection";
    EM_SCENE_CLASS_ATM = 5,                     # "ATM";"ATM";
    EM_SENCE_CLASS_INDOOR = 6,                  # "Indoor" 室内行为分析，和普通规则相同，对室内场景的算法优化版;"Indoor";
    EM_SENCE_CLASS_FACERECOGNITION = 7,         # "TargetRecognition" 目标识别;"TargetRecognition";
    EM_SENCE_CLASS_PS = 8,
    EM_SENCE_CLASS_NUMBERSTAT = 9,              # "NumberStat" 客流量统计;"NumberStat";
    EM_SENCE_CLASS_HEAT_MAP = 10,               # "HeatMap" 热度图;"HeatMap";
    EM_SENCE_CLASS_VIDEODIAGNOSIS = 11,         # "VideoDiagnosis" 视频诊断;"VideoDiagnosis";
    EM_SENCE_CLASS_VEHICLEANALYSE = 12,         # "VehicleAnalyse" 车辆特征检测分析;"VehicleAnalyse";
    EM_SENCE_CLASS_COURSERECORD = 13,           # "CourseRecord" 自动录播;"CourseRecord";
    EM_SENCE_CLASS_VEHICLE = 14,                # "Vehicle" 车载场景(车载行业用，不同于智能交通的Traffic);"Vehicle";
    EM_SENCE_CLASS_STANDUPDETECTION = 15,       # "StandUpDetection" 起立检测;"StandUpDetection";
    EM_SCENE_CLASS_GATE = 16,                   # "Gate" 卡口;"Gate";
    EM_SCENE_CLASS_SDFACEDETECTION = 17,        # "SDFaceDetect" 多预置点人脸检测，配置一条规则但可以在不同预置点下生效;"SDFaceDetect";
    EM_SCENE_CLASS_HEAT_MAP_PLAN = 18,          # "HeatMapPlan" 球机热度图计划;"HeatMapPlan";
    EM_SCENE_CLASS_NUMBERSTAT_PLAN = 19,        # "NumberStatPlan" 球机客流量统计计划;"NumberStatPlan";
    EM_SCENE_CLASS_ATMFD = 20,                  # "ATMFD"金融人脸检测，包括正常人脸、异常人脸、相邻人脸、头盔人脸等针对ATM场景特殊优化;"ATMFD";
    EM_SCENE_CLASS_HIGHWAY = 21,                # "Highway" 高速交通事件检测;"Highway";
    EM_SCENE_CLASS_CITY = 22,                   # "City" 城市交通事件检测;"City";
    EM_SCENE_CLASS_LETRACK = 23,                # "LeTrack" 民用简易跟踪;"LeTrack";
    EM_SCENE_CLASS_SCR = 24,                    # "SCR" 打靶相机;"SCR";
    EM_SCENE_CLASS_STEREO_VISION = 25,          # "StereoVision" 立体视觉(双目);"StereoVision";
    EM_SCENE_CLASS_HUMANDETECT = 26,            # "HumanDetect"人体检测;"HumanDetect";
    EM_SCENE_CLASS_FACEANALYSIS = 27,           # "FaceAnalysis" 人脸分析;"FaceAnalysis";
    EM_SCENE_CLASS_XRAY_DETECTION = 28,         # "XRayDetection" X光检测;"XRayDetection";
    EM_SCENE_CLASS_STEREO_NUMBER = 29,          # "StereoNumber" 双目相机客流量统计;"StereoNumber";
    EM_SCENE_CLASS_CROWDDISTRIMAP = 30,         # "CrowdDistriMap"人群分布图;"CrowdDistriMap";
    EM_SCENE_CLASS_OBJECTDETECT = 31,           # "ObjectDetect"目标检测;"ObjectDetect";
    EM_SCENE_CLASS_FACEATTRIBUTE = 32,          # "FaceAttribute" IVSS人脸检测;"FaceAttribute";
    EM_SCENE_CLASS_FACECOMPARE = 33,            # "FaceCompare" IVSS目标识别;"FaceCompare";
    EM_SCENE_CLASS_STEREO_BEHAVIOR = 34,        # "StereoBehavior" 立体行为分析(典型场景ATM舱);"StereoBehavior";
    EM_SCENE_CLASS_INTELLICITYMANAGER = 35,     # "IntelliCityMgr" 智慧城管;"IntelliCityMgr";
    EM_SCENE_CLASS_PROTECTIVECABIN = 36,        # "ProtectiveCabin" 防护舱（ATM舱内）;"ProtectiveCabin";
    EM_SCENE_CLASS_AIRPLANEDETECT = 37,         # "AirplaneDetect" 飞机行为检测;"AirplaneDetect";
    EM_SCENE_CLASS_CROWDPOSTURE = 38,           # "CrowdPosture" 人群态势（人群分布图服务）;"CrowdPosture";
    EM_SCENE_CLASS_PHONECALLDETECT = 39,        # "PhoneCallDetect" 打电话检测;"PhoneCallDetect";
    EM_SCENE_CLASS_SMOKEDETECTION = 40,         # "SmokeDetection" 烟雾检测;"SmokeDetection";
    EM_SCENE_CLASS_BOATDETECTION = 41,          # "BoatDetection" 船只检测;"BoatDetection";
    EM_SCENE_CLASS_SMOKINGDETECT = 42,          # "SmokingDetect" 吸烟检测;"SmokingDetect";
    EM_SCENE_CLASS_WATERMONITOR = 43,           # "WaterMonitor" 水利监测;"WaterMonitor";
    EM_SCENE_CLASS_GENERATEGRAPHDETECTION = 44, # "GenerateGraphDetection" 生成图规则;"GenerateGraphDetection";
    EM_SCENE_CLASS_TRAFFIC_PARK = 45,           # "TrafficPark" 交通停车;"TrafficPark";
    EM_SCENE_CLASS_OPERATEMONITOR = 46,         # "OperateMonitor" 作业检测;"OperateMonitor";
    EM_SCENE_CLASS_INTELLI_RETAIL = 47,         # IntelliRetail" 智慧零售大类;IntelliRetail";
    EM_SCENE_CLASS_CLASSROOM_ANALYSE = 48,      # "ClassroomAnalyse" 教育智慧课堂;"ClassroomAnalyse";
    EM_SCENE_CLASS_FEATURE_ABSTRACT = 49,       # "FeatureAbstract" 特征向量提取大类;"FeatureAbstract";
    EM_SCENE_CLASS_FACEBODY_DETECT = 50,        # "FaceBodyDetect" 人像检测大类;"FaceBodyDetect";
    EM_SCENE_CLASS_FACEBODY_ANALYSE = 51,       # "FaceBodyAnalyse"人像识别大类;"FaceBodyAnalyse";
    EM_SCENE_CLASS_VEHICLES_DISTRI = 52,        # "VehiclesDistri" 车辆密度;"VehiclesDistri";
    EM_SCENE_CLASS_INTELLI_BREED = 53,          # "IntelliBreed"智慧养殖检测;"IntelliBreed";
    EM_SCENE_CLASS_INTELLI_PS = 54,             # "IntelliPS"行为分析;"IntelliPS";
    EM_SCENE_CLASS_ELECTRIC_DETECT = 55,        # "ElectricDetect" 电力检测;"ElectricDetect";
    EM_SCENE_CLASS_RADAR_DETECT = 56,           # "RadarDetect"雷达检测;"RadarDetect";
    EM_SCENE_CLASS_PARKINGSPACE = 57,           # "ParkingSpace" 车位检测大类;"ParkingSpace";
    EM_SCENE_CLASS_INTELLI_FINANCE = 58,        # "IntelliFinance"智慧金融;"IntelliFinance";
    EM_SCENE_CLASS_CROWD_ABNORMAL = 59,         # "CrowdAbnormal" 人群异常检测;"CrowdAbnormal";
    EM_SCENE_CLASS_ANATOMYTEMP_DETECT = 60,     # "AnatomyTempDetect" 超温检测;"AnatomyTempDetect";
    EM_SCENE_CLASS_WEATHER_MONITOR = 61,        # "WeatherMonitor"天气监控;"WeatherMonitor";
    EM_SCENE_CLASS_ELEVATOR_ACCESS_CONTROL = 62,    # "ElevatorAccessControl" 电梯门禁;"ElevatorAccessControl";
    EM_SCENE_CLASS_BREAK_RULE_BUILDING = 63,    # "BreakRuleBuilding"违章建筑;"BreakRuleBuilding";
    EM_SCENE_CLASS_PANORAMA_TRAFFIC = 64,       # "PanoramaTraffic"全景交通;"PanoramaTraffic";
    EM_SCENE_CLASS_PORTRAIT_DETECT = 65,        # "PortraitDetect"人像检测;"PortraitDetect";
    EM_SCENE_CLASS_CONVEY_OR_BLOCK = 66,        # "ConveyorBlock" 传送带阻塞;"ConveyorBlock";
    EM_SCENE_CLASS_KITCHEN_ANIMAL = 67,         # "KitchenAnimal" 厨房有害动物检测;"KitchenAnimal";
    EM_SCENE_CLASS_ALLSEEINGEYE = 68,           # "AllSeeingEye" 万物检测;"AllSeeingEye";
    EM_SCENE_CLASS_DRIVE = 69,                  # "Drive" 驾驶行为分析;"Drive";
    EM_SCENE_CLASS_DRIVEASSISTANT = 70,         # "DriveAssistant" 高级驾驶辅助系统;"DriveAssistant";
    EM_SCENE_CLASS_INCABINMONITOR = 71,         # "InCabinMonitor" 车内驾驶舱监测;"InCabinMonitor";
    EM_SCENE_CLASS_BLINDSPOTDETECTION = 72,     # "BlindSpotDetection" 盲区检测;"BlindSpotDetection";
    EM_SCENE_CLASS_CONVERYER_BELT = 73,         # "ConveyerBelt" 传送带检测;"ConveyerBelt";
    EM_SCENE_CLASS_INTELLI_LOGISTICS = 74,      # "IntelliLogistics" 智慧物流;"IntelliLogistics";
    EM_SCENE_CLASS_SMOKE_FIRE = 75,             # "SmokeFire" 烟火检测;"SmokeFire";
    EM_SCENE_CLASS_OBJECT_MONITOR = 76,         # "ObjectMonitor" 物品监控;"ObjectMonitor";
    EM_SCENE_CLASS_FIRE_FACILITIES = 77,        # "FireFacilities" 消防设施检测;"FireFacilities";
    EM_SCENE_CLASS_FIRE_CONTROL = 78,           # "IntelliFireControl" 智慧消防;"IntelliFireControl";
    EM_SCENE_CLASS_INTELLI_PARKING = 79,        # "IntelliParking" 智能停车;"IntelliParking";
    EM_SCENE_CLASS_FINANCE_REGULATION = 80,     # "FinanceRegulation" 金融常规;"FinanceRegulation";
    EM_SCENE_CLASS_ENERGY = 81,                 # "Energy" 智慧能源;"Energy" Smart energy;
    EM_SCENE_CLASS_FIRE_CONTROL_EX = 82,        # "FireControl" 智慧消防;"FireControl";
    EM_SCENE_CLASS_ANIMAL_DETECTION = 83,       # "AnimalDetection" 动物检测;"AnimalDetection";
    EM_SCENE_CLASS_FIRE_CONTROL_MONITOR = 84,   # "FireControlMonitor" 火警监控;"FireControlMonitor";

class EM_ANALYSE_OBJECT_TYPE(IntEnum):
    """
    视频分析支持的对象类型
    analyse object type
    """
    EM_ANALYSE_OBJECT_TYPE_UNKNOWN = 0,         # 未知的;unknown;
    EM_ANALYSE_OBJECT_TYPE_HUMAN = 1,           # 人;human;
    EM_ANALYSE_OBJECT_TYPE_VEHICLE = 2,         # 车辆;vehicle;
    EM_ANALYSE_OBJECT_TYPE_FIRE = 3,            # 火;fire;
    EM_ANALYSE_OBJECT_TYPE_SMOKE = 4,           # 烟雾;smoke;
    EM_ANALYSE_OBJECT_TYPE_PLATE = 5,           # 片状物体;plate;
    EM_ANALYSE_OBJECT_TYPE_HUMANFACE = 6,       # 人脸;human face;
    EM_ANALYSE_OBJECT_TYPE_CONTAINER = 7,       # 货柜;container;
    EM_ANALYSE_OBJECT_TYPE_ANIMAL = 8,          # 动物;animal;
    EM_ANALYSE_OBJECT_TYPE_TRAFFICLIGHT = 9,    # 红绿灯;traffic light;
    EM_ANALYSE_OBJECT_TYPE_PASTEPAPER = 10,     # 贴纸 贴片;paster paper;
    EM_ANALYSE_OBJECT_TYPE_HUMANHEAD = 11,      # 人的头部;human head;
    EM_ANALYSE_OBJECT_TYPE_ENTITY = 12,         # 普通物体;entity;
    EM_ANALYSE_OBJECT_TYPE_PACKAGE = 13,        # 包裹;package;

class EM_STREAM_PROTOCOL_TYPE(IntEnum):
    """
    视频流协议类型
    protocol type of video stream
    """
    EM_STREAM_PROTOCOL_UNKNOWN = 0,             # 未知;unknown;
    EM_STREAM_PROTOCOL_PRIVATE_V2 = 1,          # 私有二代;private v2;
    EM_STREAM_PROTOCOL_PRIVATE_V3 = 2,          # 私有三代;private v3;
    EM_STREAM_PROTOCOL_RTSP = 3,                # rtsp;rtsp;
    EM_STREAM_PROTOCOL_ONVIF = 4,               # Onvif;Onvif;
    EM_STREAM_PROTOCOL_GB28181 = 5,             # GB28181;GB28181;
    EM_STREAM_PROTOCOL_HIKVISION = 6,
    EM_STREAM_PROTOCOL_BSCP = 7,                # 蓝星;BSCP;

class EM_INSTRUMENT_TYPE(IntEnum):
    """
    仪表类型
    Instrument type
    """
    EM_INSTRUMENT_TYPE_UNKNOWN = 0,             # 未知;Unknown;
    EM_INSTRUMENT_TYPE_STATE = 1,               # 状态识别类型;State type;
    EM_INSTRUMENT_TYPE_STATEMATCH = 2,          # 状态匹配类型;State match type;
    EM_INSTRUMENT_TYPE_METER = 3,               # 指针式表计类型;Meter type;
    EM_INSTRUMENT_TYPE_CHAR = 4,                # 数字识别类型;Digital recognition type;
    EM_INSTRUMENT_TYPE_OIL = 5,                 # 油表类型;Oil type;
    EM_INSTRUMENT_TYPE_SWIIDEN = 6,             # 开关标识;Switch identification type;
    EM_INSTRUMENT_TYPE_LIGHT = 7,               # 指示灯类型;Light type;
    EM_INSTRUMENT_TYPE_SWITCH = 8,              # 室内开关类型;Switch type;
    EM_INSTRUMENT_TYPE_APPEARANCE = 9,          # 外观检测类型;Appearance type;
    EM_INSTRUMENT_TYPE_LEVELGAUGE = 10,         # 液位计;levelgauge type;

class EM_PIC_TYPE(IntEnum):
    """
    图片类型
    Picture type
    """
    EM_PIC_TYPE_UNKNOWN = -1,                   # 未知;Unknown;
    EM_PIC_TYPE_ALGORITHMICALLY_PROCESSED = 0,  # 算法处理后的图片;Algorithmically processed picture;

class EM_DIALDETECT_TYPE(IntEnum):
    """
    仪表类型
    Dial detect type
    """
    EM_DIALDETECT_TYPE_UNKNOWN = 0,             # 未知;Unknown;
    EM_DIALDETECT_TYPE_PLATEN = 1,              # 压板检测;Pressure plate detection;
    EM_DIALDETECT_TYPE_KNIFE = 2,               # 刀闸检测;Knife detection;
    EM_DIALDETECT_TYPE_POINTERMETER = 3,        # 指针表计检测;Pointer meter detection;
    EM_DIALDETECT_TYPE_OILMETER = 4,            # 油位表计;Oil level meter detection;
    EM_DIALDETECT_TYPE_LED = 5,                 # 数码管字符检测;LED detection;
    EM_DIALDETECT_TYPE_LCD = 6,                 # 液晶屏字符检测;LCD detection;
    EM_DIALDETECT_TYPE_LIGHT = 7,               # 指示灯检测;Indicator light detection;
    EM_DIALDETECT_TYPE_SWITCH = 8,              # 旋转开关检测;Rotary switch detection;
    EM_DIALDETECT_TYPE_PESPIRATOR = 9,          # 呼吸器检测;Pespirator detection;
    EM_DIALDETECT_TYPE_CHARLNDICTOR = 10,       # 字符指示器检测;CharIndictor detection;
    EM_DIALDETECT_TYPE_POINTERLNDICTOR = 11,    # 指针指示器检测;PointerIndictor detection;
    EM_DIALDETECT_TYPE_OILLEVEL = 12,           # 液位计检测;OilLevel detection;
    EM_DIALDETECT_TYPE_DIALSWTICH = 13,         # 拨码盘字符检测;DialSwtich detection;

class EM_A_ELECTRIC_FAULT_ENABLE_RULES(IntEnum):
    """
    对应设备所使能的检测规则
    enable rules
    """
    ELECTRIC_FAULT_ENABLE_RULES_UNKNOWN = 0,    # 未知;unknown;
    ELECTRIC_FAULT_ENABLE_RULES_AIRBORNEDETECT = 1,    # 挂空悬浮物检测;Airborne Detect;
    ELECTRIC_FAULT_ENABLE_RULES_NESTDETECT = 2, # 鸟巢检测;Nest Detect;
    ELECTRIC_FAULT_ENABLE_RULES_DIALDETECT = 3, # 表盘检测;Dial Detect;
    ELECTRIC_FAULT_ENABLE_RULES_LEAKAGEDETECT = 4,    # 渗漏检测;Leakage Detect;
    ELECTRIC_FAULT_ENABLE_RULES_DOORDETECT = 5, # 箱门检测;Door Detect;
    ELECTRIC_FAULT_ENABLE_RULES_RESPIRATORDETECT = 6,    # 呼吸器检测;Respirator Detect;
    ELECTRIC_FAULT_ENABLE_RULES_SMOKINGDETECT = 7,    # 吸烟检测;Smoking detect;
    ELECTRIC_FAULT_ENABLE_RULES_INSULATORDETECT = 8,    # 绝缘子检测;Insulator detect;
    ELECTRIC_FAULT_ENABLE_RULES_COVERPLATEDETECT = 9,    # 盖板检测;Cover plate detect;
    ELECTRIC_FAULT_ENABLE_RULES_PRESSINGPLATEDETECT = 10,    # 压板检测;Pressing plate detect;
    ELECTRIC_FAULT_ENABLE_RULES_CORROSIONDETECT = 11,    # 锈蚀检测;Corrosion detect;

class EM_AIRBORNE_TYPE(IntEnum):
    """
    挂空悬浮物具体类型
    Airborne type
    """
    EM_AIRBORNE_TYPE_UNKNOWN = 0,               # 未知;unknown;
    EM_AIRBORNE_TYPE_PLASTICBAG = 1,            # 塑料袋;plastic bag;
    EM_AIRBORNE_TYPE_TEXTILE = 2,               # 织物;textile;
    EM_AIRBORNE_TYPE_KITE = 3,                  # 风筝;kete;

class EM_DIAL_STATE(IntEnum):
    """
    表盘状态
    dial state
    """
    EM_DIAL_STATE_UNKNOWN = 0,                  # 未知;unknown;
    EM_DIAL_STATE_NORMAL = 1,                   # 正常;normal;
    EM_DIAL_STATE_DIM = 2,                      # 模糊;dim;
    EM_DIAL_STATE_DIAL_BROKEN = 3,              # 表盘破损;dial broken;
    EM_DIAL_STATE_SHELL_BROKEN = 4,             # 外壳破裂;shell broken;
    EM_DIAL_STATE_ABNORMAL_READING = 5,         # 读数异常;abnormal reading;

class EM_DOOR_STATE(IntEnum):
    """
    箱门状态
    door state
    """
    EM_DOOR_STATE_UNKNOWN = 0,                  # 未知;unknown;
    EM_DOOR_STATE_OPEN = 1,                     # 打开;open;
    EM_DOOR_STATE_CLOSE = 2,                    # 关闭;close;

class EM_RESPIRATOR_STATE(IntEnum):
    """
    呼吸器状态
    Respirator state
    """
    EM_RESPIRATOR_STATE_UNKNOWN = 0,            # 未知;unknown;
    EM_RESPIRATOR_STATE_NORMAL = 1,             # 正常;normal;
    EM_RESPIRATOR_STATE_SILICA_GEL_COLOR_CHANGE = 2,    # 硅胶变色;silica gel color change;
    EM_RESPIRATOR_STATE_SILICA_GEL_BARREL_BROKEN = 3,    # 硅胶桶破损;silica gel barrel broken;
    EM_RESPIRATOR_STATE_ABNORMAL_OIL_LEVEL = 4, # 油位异常;oil level;

class EM_INSULATOR_STATE(IntEnum):
    """
    绝缘子状态
    insulator state
    """
    EM_INSULATOR_STATE_UNKNOWN = 0,             # 未知;unknown;
    EM_INSULATOR_STATE_NORMAL = 1,              # 正常;normal;
    EM_INSULATOR_STATE_BROKEN = 2,              # 破裂;broken;

class EM_COVER_PLATE_STATE(IntEnum):
    """
    盖板状态
    cover plate state
    """
    EM_COVER_PLATE_STATE_UNKNOWN = 0,           # 未知;unknown;
    EM_COVER_PLATE_STATE_NORMAL = 1,            # 正常;normal;
    EM_COVER_PLATE_STATE_BROKEN = 2,            # 破裂;broken;

class EM_PRESSING_PLATE_STATE(IntEnum):
    """
    压板状态
    pressing plate state
    """
    EM_PRESSING_PLATE_STATE_UNKNOWN = 0,        # 未知;unknown;
    EM_PRESSING_PLATE_STATE_DISCONNECT = 1,     # 断开;disconnect;
    EM_PRESSING_PLATE_STATE_CLOSE = 2,          # 闭合;close;

class EM_FILTER_IMAGE_TYPE(IntEnum):
    """
    返回的图片类型
    image data type
    """
    EM_FILTER_IMAGE_UNKNOWN = 0,                # 未知;unknown;
    EM_FILTER_IMAGE_OBJECT = 1,                 # 上报目标抠图;object image;
    EM_FILTER_IMAGE_SCENE = 2,                  # 上报场景大图;scene image;

class EM_FILE_ANALYSE_STATE(IntEnum):
    """
    文件分析状态
    file analyse state
    """
    EM_FILE_ANALYSE_UNKNOWN = -1,               # 未知;unknown;
    EM_FILE_ANALYSE_EXECUTING = 0,              # 分析中;in analysis;
    EM_FILE_ANALYSE_FINISH = 1,                 # 分析完成;finish;
    EM_FILE_ANALYSE_FAILED = 2,                 # 分析失败;failed;

class EM_ANALYSE_EVENT_TYPE(IntEnum):
    """
    事件类型
    event type
    """
    EM_ANALYSE_EVENT_UNKNOWN = 0,               # 未知;unknown;
    EM_ANALYSE_EVENT_ALL = 1,                   # 所有事件;all;
    EM_ANALYSE_EVENT_FACE_DETECTION = 2,        # 人脸检测事件, 对应结构体 DEV_EVENT_FACEDETECT_INFO;face detection event, corresponding to DEV_EVENT_FACEDETECT_INFO;
    EM_ANALYSE_EVENT_FACE_RECOGNITION = 3,      # 目标识别事件, 对应结构体 DEV_EVENT_FACERECOGNITION_INFO;target recognition event, corresponding to DEV_EVENT_FACERECOGNITION_INFO;
    EM_ANALYSE_EVENT_TRAFFICJUNCTION = 4,       # 交通路口事件, 对应结构体 DEV_EVENT_TRAFFICJUNCTION_INFO;traffic junction event, corresponding to DEV_EVENT_TRAFFICJUNCTION_INFO;
    EM_ANALYSE_EVENT_HUMANTRAIT = 5,            # 人体特征事件, 对应结构体 DEV_EVENT_HUMANTRAIT_INFO;humantrait event, corresponding to DEV_EVENT_HUMANTRAIT_INFO;
    EM_ANALYSE_EVENT_XRAY_DETECTION = 6,        # X光机检测事件, 对应结构体 DEV_EVENT_XRAY_DETECTION_INFO;X ray detection event, corresponding to DEV_EVENT_XRAY_DETECTION_INFO;
    EM_ANALYSE_EVENT_WORKCLOTHESDETECT = 7,     # 工装(安全帽/工作服等)检测事件, 对应结构体 DEV_EVENT_WORKCLOTHES_DETECT_INFO;work clothes(helmet/clothes) detection, corresponding to DEV_EVENT_WORKCLOTHESDETECT_INFO;
    EM_ANALYSE_EVENT_WORKSTATDETECTION = 8,     # 作业检测事件, 对应结构体 DEV_EVENT_WORKSTATDETECTION_INFO;work state detection, corresponding to DEV_EVENT_WORKSTATDETECTION_INFO;
    EM_ANALYSE_EVENT_CORSSLINEDETECTION = 9,    # 警戒线事件, 对应结构体 DEV_EVENT_CROSSLINE_INFO;cross line event, corresponding to DEV_EVENT_CROSSLINE_INFO;
    EM_ANALYSE_EVENT_CROSSREGIONDETECTION = 10, # 警戒区事件, 对应结构体 DEV_EVENT_CROSSREGION_INFO;cross region event, corresponding to DEV_EVENT_CROSSREGION_INFO;
    EM_ANALYSE_EVENT_FEATURE_ABSTRACT = 11,     # 特征提取事件 DEV_EVENT_FEATURE_ABSTRACT_INFO;Feature abstract, corresponding to DEV_EVENT_FEATURE_ABSTRACT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_GLOVE_DETECT = 12,    # 电力检测手套检测事件, 对应结构体 DEV_EVENT_ELECTRIC_GLOVE_DETECT_INFO;Electric glove detection, corresponding to DEV_EVENT_ELECTRIC_GLOVE_DETECT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_LADDER_DETECT = 13,    # 电力检测梯子检测事件, 对应结构体 DEV_EVENT_ELECTRIC_LADDER_DETECT_INFO;Electric ladder detection, corresponding to DEV_EVENT_ELECTRIC_LADDER_DETECT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_CURTAIN_DETECT = 14,    # 电力检测布幔检测事件, 对应结构体 DEV_EVENT_ELECTRIC_CURTAIN_DETECT_INFO;Electric curtain detection, corresponding to DEV_EVENT_ELECTRIC_CURTAIN_DETECT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_FENCE_DETECT = 15,    # 电力检测围栏检测事件, 对应结构体 DEV_EVENT_ELECTRIC_FENCE_DETECT_INFO;Electric fence detection, corresponding to DEV_EVENT_ELECTRIC_FENCE_DETECT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_SIGNBOARD_DETECT = 16,    # 电力检测标识牌检测事件, 对应结构体 DEV_EVENT_ELECTRIC_SIGNBOARD_DETECT_INFO;Electric signboard detection, corresponding to DEV_EVENT_ELECTRIC_SIGNBOARD_DETECT_INFO;
    EM_ANALYSE_EVENT_ELECTRIC_BELT_DETECT = 17, # 电力检测安全带检测事件, 对应结构体 DEV_EVENT_ELECTRIC_BELT_DETECT_INFO;Electric belt detection, corresponding to DEV_EVENT_ELECTRIC_BELT_DETECT_INFO;
    EM_ANALYSE_EVENT_BANNER_DETECTION = 18,     # 拉横幅检测事件, 对应的结构体 DEV_EVENT_BANNER_DETECTION_INFO;Banner detection corresponding to DEV_EVENT_BANNER_DETECTION_INFO;
    EM_ANALYSE_EVENT_SMART_KITCHEN_CLOTHES_DETECTION = 19,    # 智慧厨房穿着检测事件, 对应结构体 DEV_EVENT_SMART_KITCHEN_CLOTHES_DETECTION_INFO;Smart Kitchen Clothes Detection, corresponding to DEV_EVENT_SMART_KITCHEN_CLOTHES_DETECTION_INFO;
    EM_ANALYSE_EVENT_WATER_STAGE_MONITOR = 20,  # 水位监测事件, 对应结构体DEV_EVENT_WATER_STAGE_MONITOR_INFO;Water stage monitor, corresponding to DEV_EVENT_WATER_STAGE_MONITOR_INFO;
    EM_ANALYSE_EVENT_FLOATINGOBJECT_DETECTION = 21,    # 漂浮物检测事件, 对应结构体 DEV_EVENT_FLOATINGOBJECT_DETECTION_INFO;Floating object detection, corresponding to DEV_EVENT_FLOATINGOBJECT_DETECTION_INFO;
    EM_ANALYSE_EVENT_IVS_RIOTERDETECTION = 22,  # 人群聚集 对应结构体 DEV_EVENT_RIOTERL_INFO);Rioter detection, corresponding to DEV_EVENT_RIOTERL_INFO;
    EM_ANALYSE_EVENT_IVS_LEFTDETECTION = 23,    # 物品遗留事件 对应结构体 DEV_EVENT_LEFT_INFO;Left detection, corresponding to DEV_EVENT_LEFT_INFO;
    EM_ANALYSE_EVENT_IVS_PARKINGDETECTION = 24, # 非法停车事件 对应结构体 DEV_EVENT_PARKINGDETECTION_INFO;Parking detection, corresponding to DEV_EVENT_PARKINGDETECTION_INFO;
    EM_ANALYSE_EVENT_IVS_WANDERDETECTION = 25,  # 徘徊事件对应结构体 DEV_EVENT_WANDER_INFO;Wander detection, corresponding to DEV_EVENT_WANDER_INFO;
    EM_ANALYSE_EVENT_IVS_VIDEOABNORMALDETECTION = 26,    # 视频异常对应结构体 DEV_EVENT_VIDEOABNORMALDETECTION_INFO;Video abnormal detection, corresponding to DEV_EVENT_VIDEOABNORMALDETECTION_INFO;
    EM_ANALYSE_EVENT_MOVEDETECTION = 27,        # 运动检测事件, 对应结构体 DEV_EVENT_MOVE_INFO;Move detection, corresponding to DEV_EVENT_MOVE_INFO;
    EM_ANALYSE_EVENT_VIDEO_NORMAL_DETECTION = 28,    # 视频正常事件,在视频诊断检测周期结束时,将未报错的诊断项上报正常事件,对应结构体 DEV_EVENT_VIDEO_NORMAL_DETECTION_INFO;When the video diagnosis detection cycle ends, the diagnostic items that have not reported errors are reported to the normal events,corresponding to DEV_EVENT_VIDEO_NORMAL_DETECTION_INFO;
    EM_ANALYSE_EVENT_CONVEYER_BELT_BULK = 29,   # 传送带大块异物检测事件, 对应结构体 DEV_EVENT_CONVEYER_BELT_BULK_INFO;Conveyer belt bulk detection, corresponding to DEV_EVENT_CONVEYER_BELT_BULK_INFO;
    EM_ANALYSE_EVENT_CONVEYER_BELT_NONLOAD = 30,    # 传送带空载检测事件, 对应结构体 DEV_EVENT_CONVEYER_BELT_NONLOAD_INFO;Conveyer belt nonload detection, corresponding to DEV_EVENT_CONVEYER_BELT_NONLOAD_INFO;
    EM_ANALYSE_EVENT_CONVEYER_BELT_RUNOFF = 31, # 传送带跑偏检测事件, 对应结构体 DEV_EVENT_CONVEYER_BELT_RUNOFF_INFO;Conveyer belt runoff detection, corresponding to DEV_EVENT_CONVEYER_BELT_RUNOFF_INFO;
    EM_ANALYSE_EVENT_CONVEYER_BELT_BLOCK = 32,  # 传送带阻塞检测事件, 对应结构体 DEV_EVENT_CONVEYORBLOCK_DETECTION_INFO;Conveyer belt block detection, corresponding to DEV_EVENT_CONVEYORBLOCK_DETECTION_INFO;
    EM_ANALYSE_EVENT_NUMBER_STAT = 33,          # 数量统计事件, 对应 结构体 DEV_EVENT_NUMBERSTAT_INFO;Number stat event, corresponding to DEV_EVENT_NUMBERSTAT_INFO;
    EM_ANALYSE_EVENT_FIGHTDETECTION = 34,       # 斗殴事件, 对应结构体 DEV_EVENT_FIGHT_INFO;Fight detection, corresponding to DEV_EVENT_FIGHT_INFO;
    EM_ANALYSE_EVENT_SMOKEDETECTION = 35,       # 烟雾报警检测事件, 对应结构体 DEV_EVENT_SMOKE_INFO;Smoke detection, corresponding to DEV_EVENT_SMOKE_INFO;
    EM_ANALYSE_EVENT_FIREDETECTION = 36,        # 火警检测事件, 对应结构体 DEV_EVENT_FIRE_INFO;Fire detection, corresponding to DEV_EVENT_FIRE_INFO;
    EM_ANALYSE_EVENT_PHONECALL_DETECT = 37,     # 打电话检测事件, 对应结构体 DEV_EVENT_PHONECALL_DETECT_INFO;Phone call detection, corresponding to DEV_EVENT_PHONECALL_DETECT_INFO;
    EM_ANALYSE_EVENT_SMOKING_DETECT = 38,       # 吸烟检测事件, 对应结构体 DEV_EVENT_SMOKING_DETECT_INFO;Smoking detection, corresponding to DEV_EVENT_SMOKING_DETECT_INFO;
    EM_ANALYSE_EVENT_TUMBLE_DETECTION = 39,     # 跌倒检测事件, 对应结构体 DEV_EVENT_TUMBLE_DETECTION_INFO;Tumble detection, corresponding to DEV_EVENT_TUMBLE_DETECTION_INFO;
    EM_ANALYSE_EVENT_WATER_LEVEL_DETECTION = 40,    # 水位尺检测事件, 对应结构体 DEV_EVENT_WATER_LEVEL_DETECTION_INFO;Water level detection, corresponding to DEV_EVENT_WATER_LEVEL_DETECTION_INFO;
    EM_ANALYSE_EVENT_CLIMBDETECTION = 41,       # 攀高检测事件, 对应结构体 DEV_EVENT_IVS_CLIMB_INFO;Climb detection, corresponding to DEV_EVENT_IVS_CLIMB_INFO;
    EM_ANALYSE_EVENT_MAN_NUM_DETECTION = 42,    # 立体视觉区域内人数统计事件, 对应结构体DEV_EVENT_MANNUM_DETECTION_INFO;Event of regional population statistics, corresponding to DEV_EVENT_MANNUM_DETECTION_INFO;
    EM_ANALYSE_EVENT_DIALRECOGNITION = 43,      # 仪表检测事件, 对应结构体 DEV_EVENT_DIALRECOGNITION_INFO;Dial recognition, corresponding to DEV_EVENT_DIALRECOGNITION_INFO;
    EM_ANALYSE_EVENT_ELECTRICFAULT_DETECT = 44, # 仪表类缺陷检测事件, 对应结构体DEV_EVENT_ELECTRICFAULTDETECT_INFO;Electric fault detection, corresponding to DEV_EVENT_ELECTRICFAULTDETECT_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_ROAD_BLOCK = 45,    # 交通路障检测事件,对应结构体 DEV_EVENT_TRAFFIC_ROAD_BLOCK_INFO;Traffic road block detection,corresponding to DEV_EVENT_TRAFFIC_ROAD_BLOCK_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_ROAD_CONSTRUCTION = 46,    # 交通道路施工检测事件,对应结构体 DEV_EVENT_TRAFFIC_ROAD_CONSTRUCTION_INFO;Traffic road construction detection,corresponding to DEV_EVENT_TRAFFIC_ROAD_CONSTRUCTION_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_FLOWSTATE = 47,    # 交通流量统计事件,对应结构体 DEV_EVENT_TRAFFIC_FLOW_STATE;Traffic flowstate detection,corresponding to DEV_EVENT_TRAFFIC_FLOW_STATE;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_OVERSPEED = 48,    # 超速事件,对应结构体 DEV_EVENT_TRAFFIC_OVERSPEED_INFO;Traffic overspeed detection,corresponding to DEV_EVENT_TRAFFIC_OVERSPEED_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_UNDERSPEED = 49,    # 欠速事件,对应结构体 DEV_EVENT_TRAFFIC_UNDERSPEED_INFO;Traffic underspeed detection,corresponding to DEV_EVENT_TRAFFIC_UNDERSPEED_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_OVERYELLOWLINE = 50,    # 压黄线事件,对应结构体 DEV_EVENT_TRAFFIC_OVERYELLOWLINE_INFO;Traffic over yeallow line detection,corresponding to DEV_EVENT_TRAFFIC_OVERYELLOWLINE_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_CROSSLANE = 51,    # 违章变道事件, 对应结构体 DEV_EVENT_TRAFFIC_CROSSLANE_INFO;Traffic crosslane detection, corresponding to DEV_EVENT_TRAFFIC_CROSSLANE_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFICJAM = 52,       # 交通拥堵事件, 对应结构体 DEV_EVENT_TRAFFICJAM_INFO;TrafficJam detection, corresponding to DEV_EVENT_TRAFFICJAM_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_PEDESTRAIN = 53,    # 交通行人事件, 对应结构体 DEV_EVENT_TRAFFIC_PEDESTRAIN_INFO;Traffic pedestrain detection, corresponding to DEV_EVENT_TRAFFIC_PEDESTRAIN_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_THROW = 54,    # 抛洒物事件, 对应结构体 DEV_EVENT_TRAFFIC_THROW_INFO;Traffic throw detection, corresponding to DEV_EVENT_TRAFFIC_THROW_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_RETROGRADE = 55,    # 交通逆行事件, 对应结构体 DEV_EVENT_TRAFFIC_RETROGRADE_INFO;Traffic retrograde detection, corresponding to DEV_EVENT_TRAFFIC_RETROGRADE_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFICACCIDENT = 56,  # 交通事故事件, 对应结构体 DEV_EVENT_TRAFFICACCIDENT_INFO;Traffic accident detection, corresponding to DEV_EVENT_TRAFFICACCIDENT_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_BACKING = 57,  # 倒车事件, 对应结构体 DEV_EVENT_IVS_TRAFFIC_BACKING_INFO;Traffic backing detection, corresponding to DEV_EVENT_IVS_TRAFFIC_BACKING_INFO;
    EM_ANALYSE_EVENT_IVS_FOG_DETECTION = 58,    # 起雾检测事件, 对应结构体 DEV_EVENT_FOG_DETECTION;Fog detection, corresponding to DEV_EVENT_FOG_DETECTION;
    EM_ANALYSE_EVENT_IVS_CROSSREGIONDETECTION = 59,    # 警戒区事件, 对应结构体 DEV_EVENT_CROSSREGION_INFO;Cross region detection, corresponding to DEV_EVENT_CROSSREGION_INFO;
    EM_ANALYSE_EVENT_IVS_TRAFFIC_PARKING = 60,  # 交通违章停车事件，对应结构体 DEV_EVENT_TRAFFIC_PARKING_INFO;Traffic Parking detection,corresponding to DEV_EVENT_TRAFFIC_PARKING_INFO;
    EM_ANALYSE_EVENT_IVS_FINANCE_CASH_TRANSACTION = 61,    # 智慧金融现金交易检测事件,对应结构体 DEV_EVENT_FINANCE_CASH_TRANSACTION_INFO;Finance CASH detection,corresponding to DEV_EVENT_FINANCE_CASH_TRANSACTION_INFO;
    EM_ANALYSE_EVENT_IVS_LEAVEDETECTION = 62,   # 离岗检测事件,对应结构体 DEV_EVENT_IVS_LEAVE_INFO;LEAVE detection ,corresponding to DEV_EVENT_IVS_LEAVE_INFO;
    EM_ANALYSE_EVENT_IVS_LADLE_NO_DETECTION = 63,    # 钢包编号识别事件,对应结构体 DEV_EVENT_LADLE_NO_DETECTION_INFO;Ladle number identification event,corresponding to DEV_EVENT_LADLE_NO_DETECTION_INFO;
    EM_ANALYSE_EVENT_IVS_STAYDETECTION = 64,    # 停留事件,对应结构体 DEV_EVENT_STAY_INFO;Stay event,corresponding to DEV_EVENT_STAY_INFO;
    EM_ANALYSE_EVENT_IVS_NEAR_OBJECT_DETECT = 65,    # 近物体检测事件,对应结构体 DEV_EVENT_NEAR_OBJECT_DETECT_INFO;Near object detection event,corresponding to DEV_EVENT_NEAR_OBJECT_DETECT_INFO;
    EM_ANALYSE_EVENT_IVS_CRANE_LOAD_STAY_DETECTION = 66,    # 天车吊物滞留事件,对应结构体 DEV_EVENT_CRANE_LOAD_STAY_DETECTION_INFO;Detention of overhead crane lifting objects,corresponding to DEV_EVENT_CRANE_LOAD_STAY_DETECTION_INFO;
    EM_ANALYSE_EVENT_CROSSLINEDETECTION_EX = 2000,    # 警戒线事件(扩展), 对应结构体 DEV_EVENT_CROSSLINE_INFO_EX;cross line(expansion) event, corresponding to DEV_EVENT_CROSSLINE_INFO_EX;

class EM_A_NET_CROSSLINE_DIRECTION_INFO(IntEnum):
    """
    警戒线入侵方向
    Warning line intrusion direction
    """
    EM_CROSSLINE_DIRECTION_UNKNOW = 0,
    EM_CROSSLINE_DIRECTION_LEFT2RIGHT = 1,      # 左到右;From left to right;
    EM_CROSSLINE_DIRECTION_RIGHT2LEFT = 2,      # 右到左;From right to left;
    EM_CROSSLINE_DIRECTION_ANY = 3,

class EM_A_NET_CROSSREGION_DIRECTION_INFO(IntEnum):
    """
    警戒区入侵方向
    Waring zone intrusion direction
    """
    EM_CROSSREGION_DIRECTION_UNKNOW = 0,
    EM_CROSSREGION_DIRECTION_ENTER = 1,         # 进入;Entry;
    EM_CROSSREGION_DIRECTION_LEAVE = 2,         # 离开;Exit;
    EM_CROSSREGION_DIRECTION_APPEAR = 3,        # 出现;Appear;
    EM_CROSSREGION_DIRECTION_DISAPPEAR = 4,     # 消失;Disappear;

class EM_A_NET_CROSSREGION_ACTION_INFO(IntEnum):
    """
    区域检测事件动作
    Warning zone detected operation type
    """
    EM_CROSSREGION_ACTION_UNKNOW = 0,
    EM_CROSSREGION_ACTION_INSIDE = 1,           # 在区域内;In the area;
    EM_CROSSREGION_ACTION_CROSS = 2,            # 穿越区域;Cross area;
    EM_CROSSREGION_ACTION_APPEAR = 3,           # 出现;Appear;
    EM_CROSSREGION_ACTION_DISAPPEAR = 4,        # 消失;Disappear;

class EM_A_DEVICE_PROTOCOL(IntEnum):
    """
    设备协议类型
    Device protocol type
    """
    EM_A_PROTOCOL_PRIVATE2 = 0,                 # 私有2代协议;private 2nd protocol;
    EM_A_PROTOCOL_PRIVATE3 = 1,                 # 私有3代协议;private 3rd protocol;
    EM_A_PROTOCOL_ONVIF = 2,                    # Onvif;Onvif;
    EM_A_PROTOCOL_VNC = 3,                      # 虚拟网络计算机;virtual network computer;
    EM_A_PROTOCOL_TS = 4,                       # 标准TS;Standard TS;
    EM_A_PROTOCOL_ECLOUD = 5,                   # 云睿接入;ECloud;
    EM_A_PROTOCOL_PRIVATE = 100,                # 私有协议;private protocol of private;
    EM_A_PROTOCOL_AEBELL = 101,                 # 美电贝尔;aebell;
    EM_A_PROTOCOL_PANASONIC = 102,              # 松下;panasonic;
    EM_A_PROTOCOL_SONY = 103,                   # 索尼;sony;
    EM_A_PROTOCOL_DYNACOLOR = 104,              # Dynacolor;Dynacolor;
    EM_A_PROTOCOL_TCWS = 105,                   # 天城威视;tcsw;
    EM_A_PROTOCOL_SAMSUNG = 106,                # 三星;sansung;
    EM_A_PROTOCOL_YOKO = 107,                   # YOKO;YOKO;
    EM_A_PROTOCOL_AXIS = 108,                   # 安讯视;axis;
    EM_A_PROTOCOL_SANYO = 109,                  # 三洋;sanyo;
    EM_A_PROTOCOL_BOSH = 110,                   # Bosch;Bosch;
    EM_A_PROTOCOL_PECLO = 111,                  # Peclo;Peclo;
    EM_A_PROTOCOL_PROVIDEO = 112,               # Provideo;Provideo;
    EM_A_PROTOCOL_ACTI = 113,                   # ACTi;ACTi;
    EM_A_PROTOCOL_VIVOTEK = 114,                # Vivotek;Vivotek;
    EM_A_PROTOCOL_ARECONT = 115,                # Arecont;Arecont;
    EM_A_PROTOCOL_PRIVATEEH = 116,              # PrivateEH;PrivateEH;
    EM_A_PROTOCOL_IMATEK = 117,                 # IMatek;IMatek;
    EM_A_PROTOCOL_SHANY = 118,                  # Shany;Shany;
    EM_A_PROTOCOL_VIDEOTREC = 119,              # 动力盈科;videotrec;
    EM_A_PROTOCOL_URA = 120,                    # Ura;Ura;
    EM_A_PROTOCOL_BITICINO = 121,               # Bticino;Bticino;
    EM_A_PROTOCOL_ONVIF2 = 122,                 # Onvif协议类型, 同PROTOCOL_ONVIF;Onvif's protocol type, same to PROTOCOL_ONVIF;
    EM_A_PROTOCOL_SHEPHERD = 123,               # 视霸;shepherd;
    EM_A_PROTOCOL_YAAN = 124,                   # 亚安;yaan;
    EM_A_PROTOCOL_AIRPOINT = 125,               # Airpop;Airpop;
    EM_A_PROTOCOL_TYCO = 126,                   # TYCO;TYCO;
    EM_A_PROTOCOL_XUNMEI = 127,                 # 讯美;xunmei;
    EM_A_PROTOCOL_HIKVISION = 128,
    EM_A_PROTOCOL_LG = 129,                     # LG;LG;
    EM_A_PROTOCOL_AOQIMAN = 130,                # 奥奇曼;aoqiman;
    EM_A_PROTOCOL_BAOKANG = 131,                # 宝康;baokang;
    EM_A_PROTOCOL_WATCHNET = 132,               # Watchnet;Watchnet;
    EM_A_PROTOCOL_XVISION = 133,                # Xvision;Xvision;
    EM_A_PROTOCOL_FUSITSU = 134,                # 富士通;fusitsu;
    EM_A_PROTOCOL_CANON = 135,                  # Canon;Canon;
    EM_A_PROTOCOL_GE = 136,                     # GE;GE;
    EM_A_PROTOCOL_Basler = 137,                 # 巴斯勒;basler;
    EM_A_PROTOCOL_Patro = 138,                  # 帕特罗;patro;
    EM_A_PROTOCOL_CPKNC = 139,                  # CPPLUS K系列;CPPLUS K series;
    EM_A_PROTOCOL_CPRNC = 140,                  # CPPLUS R系列;CPPLUS R series;
    EM_A_PROTOCOL_CPUNC = 141,                  # CPPLUS U系列;CPPLUS U series;
    EM_A_PROTOCOL_CPPLUS = 142,                 # CPPLUS IPC;CPPLUS IPC;
    EM_A_PROTOCOL_XunmeiS = 143,                # 讯美s,实际协议为Onvif;xunmeis,protocal is Onvif;
    EM_A_PROTOCOL_GDDW = 144,                   # 广东电网;GDDW;
    EM_A_PROTOCOL_PSIA = 145,                   # PSIA;PSIA;
    EM_A_PROTOCOL_GB2818 = 146,                 # GB2818;GB2818;
    EM_A_PROTOCOL_GDYX = 147,                   # GDYX;GDYX;
    EM_A_PROTOCOL_OTHER = 148,                  # 由用户自定义;others;
    EM_A_PROTOCOL_MULTICAST = 179,              # 组播，实现组播功能，当成第三方设备接入来处理;Multicast, to achieve multicast function, as a third-party device access to deal with;
    EM_A_PROTOCOL_MULTICASTTS = 185,            # 组播，处理TS组播功能，当成第三方设备接入来处理;MulticastTs, to achieve TS multicast function, as a third-party device access to deal with;

class EM_STREAM_TRANSMISSION_SERVICE_TYPE(IntEnum):
    """
    指码流传输的服务类型
    service type
    """
    EM_STREAM_TRANSMISSION_SERVICE_TYPE_UNKNOWN = 0,    # 未知;Unknown;
    EM_STREAM_TRANSMISSION_SERVICE_TYPE_TCP = 1,    # TCP;TCP;
    EM_STREAM_TRANSMISSION_SERVICE_TYPE_UDP = 2,    # UDP;UDP;
    EM_STREAM_TRANSMISSION_SERVICE_TYPE_MCAST = 3,    # MCAST;MCAST;
    EM_STREAM_TRANSMISSION_SERVICE_TYPE_AUTO = 4,    # AUTO;AUTO;

class EM_ENCRYPT_LEVEL(IntEnum):
    """
    加密等级
    Encrypt level
    """
    EM_ENCRYPT_LEVEL_UNKNOWN = 0,               # 未知;Unknown;
    EM_ENCRYPT_LEVEL_NONE = 1,                  # 不加密;Not encrypt;
    EM_ENCRYPT_LEVEL_IFRAME256 = 2,             # 加密I帧前256字节;Encrypt 256 byte in Iframe;
    EM_ENCRYPT_LEVEL_IFRAME_WHOLE = 3,          # 加密整个I帧;Encrypt the whole Iframe;
    EM_ENCRYPT_LEVEL_IAXFRAME = 4,              # 对I帧, 音频帧及其他辅助帧进行加密;Encrypt the I frame , audio frame and other auxiliary frame;

class EM_ENCRYPT_ALGORITHM_TYPE(IntEnum):
    """
    码流加密方式
    The type of stream encrypt algorithm
    """
    EM_ENCRYPT_ALGORITHM_UNKNOWN = 0,           # 未知;Unknown;
    EM_ENCRYPT_ALGORITHM_AES = 1,               # AES加密;AES;
    EM_ENCRYPT_ALGORITHM_DES = 2,               # DES加密;DES;
    EM_ENCRYPT_ALGORITHM_3DES = 3,              # 3DES加密;3DES;

class EM_KEY_EXCHANGE_TYPE(IntEnum):
    """
    密钥交换方式
    The type of exchange key
    """
    EM_KEY_EXCHANGE_UNKNOWN = 0,                # 未知;Unknown;
    EM_KEY_EXCHANGE_MIKEY = 1,                  # Mikey密钥;Mikey key;
    EM_KEY_EXCHANGE_PSK = 2,                    # 预共享密钥;share key;
    EM_KEY_EXCHANGE_PK = 3,                     # 公共密钥;public key;
    EM_KEY_EXCHANGE_DH = 4,                     # 霍夫曼密钥;hoffman key;

class EM_A_NET_LOGIC_CHN_TYPE(IntEnum):
    """
    通道类型
    Channel Types
    """
    LOGIC_CHN_UNKNOWN = 0,                      # 未知;Unknow;
    LOGIC_CHN_LOCAL = 1,                        # 本地通道;Local channel;
    LOGIC_CHN_REMOTE = 2,                       # 远程通道;Remote access channel;
    LOGIC_CHN_COMPOSE = 3,                      # 合成通道, 对于庭审设备包含画中画通道和混音通道;Synthesis of channel, for the judicial equipment contains picture in picture channel and mixing channel;
    LOGIC_CHN_MATRIX = 4,                       # 模拟矩阵通道;matrix channel, including analog matrix and digital matrix;
    LOGIC_CHN_CASCADE = 5,                      # 级联通道;cascading channel;

class EM_VIDEO_STREAM(IntEnum):
    """
    视频码流
    video stream
    """
    EM_VIDEO_STREAM_UNKNOWN = 0,                # 未知;unknown;
    EM_VIDEO_STREAM_MAIN = 1,                   # 主码流;main;
    EM_VIDEO_STREAM_EXTRA1 = 2,                 # 辅码流1;extra1;
    EM_VIDEO_STREAM_EXTRA2 = 3,                 # 辅码流2;extra2;
    EM_VIDEO_STREAM_EXTRA3 = 4,                 # 辅码流3;extra3;
    EM_VIDEO_STREAM_AUTO = 5,                   # 自动选择合适码流;auto;
    EM_VIDEO_STREAM_PREVIEW = 6,                # 预览裸数据码流;preview;
    EM_VIDEO_STREAM_NO_VIDEO_JUST_AUDIO = 7,    # 无视频码流(纯音频流);no video stream, just audio stream;

class EM_A_NET_EM_RTMP_MANAGER_STATUS(IntEnum):
    """
    状态变化
    State change
    """
    NET_EM_RTMP_MANAGER_STATUS_UNKNOWN = -1,    # 未知;Unknown;
    NET_EM_RTMP_MANAGER_STATUS_NOT_ENABLED = 0, # 未开启推流;Streaming is not enabled;
    NET_EM_RTMP_MANAGER_STATUS_PUSH_FLOW = 1,   # 推流中;Push flow;
    NET_EM_RTMP_MANAGER_STATUS_PUSH_FLOW_END_NORMALLY = 2,    # 推流正常结束;The push flow ends normally;
    NET_EM_RTMP_MANAGER_STATUS_FAILED = 3,      # 推流失败;Streaming failed;
    NET_EM_RTMP_MANAGER_STATUS_STOP = 4,        # 推流暂停;Streaming stop;

class EM_A_NET_EM_RTMP_MANAGER_ERRCODE(IntEnum):
    """
    错误码
    Error code
    """
    NET_EM_RTMP_MANAGER_ERRCODE_UNKNOWN = 0,    # 未知;unknown;
    NET_EM_RTMP_MANAGER_ERRCODE_NOERROR = 1,    # 无错误;No error;
    NET_EM_RTMP_MANAGER_ERRCODE_STREAMID_NOT_EXIST = 2,    # 推流ID不存在;Push ID not exist;
    NET_EM_RTMP_MANAGER_ERRCODE_OTHER_ERRORS = 3,    # 其他错误;Other error;

class EM_A_NET_EM_RTMP_MANAGER_OPER_TYPE(IntEnum):
    """
    RTMP推流操作类型
    RTMP Streaming operation type
    """
    NET_EM_RTMP_MANAGER_OPER_TYPE_GETCAPS = 0,  # 获取设备RTMP推流能力, 对应结构体 pstInParam = NET_IN_RTMP_MANAGER_GETCAPS, pstOutParam = NET_OUT_RTMP_MANAGER_GETCAPS;Obtain RTMP streaming capability of the device, Corresponding structure pstInParam = NET_IN_RTMP_MANAGER_GETCAPS, pstOutParam = NET_OUT_RTMP_MANAGER_GETCAPS;
    NET_EM_RTMP_MANAGER_OPER_TYPE_ADD = 1,      # 添加推流地址, 对应结构体 pstInParam = NET_IN_RTMP_MANAGER_ADD, pstOutParam = NET_OUT_RTMP_MANAGER_ADD;Add streaming address, Corresponding structure pstInParam = NET_IN_RTMP_MANAGER_ADD, pstOutParam = NET_OUT_RTMP_MANAGER_ADD;
    NET_EM_RTMP_MANAGER_OPER_TYPE_REMOVE = 2,   # 删除推流地址, 对应结构体 pstInParam = NET_IN_RTMP_MANAGER_REMOVE, pstOutParam = NET_OUT_RTMP_MANAGER_REMOVE;Remove streaming address, Corresponding structure pstInParam = NET_IN_RTMP_MANAGER_REMOVE, pstOutParam = NET_OUT_RTMP_MANAGER_REMOVE;
    NET_EM_RTMP_MANAGER_OPER_TYPE_START = 3,    # 启动推流, 对应结构体 pstInParam = NET_IN_RTMP_MANAGER_START, pstOutParam = NET_OUT_RTMP_MANAGER_START;Start streaming, Corresponding structure pstInParam = NET_IN_RTMP_MANAGER_START, pstOutParam = NET_OUT_RTMP_MANAGER_START;
    NET_EM_RTMP_MANAGER_OPER_TYPE_STOP = 4,     # 停止推流, 对应结构体 pstInParam = NET_IN_RTMP_MANAGER_STOP, pstOutParam = NET_OUT_RTMP_MANAGER_STOP;Stop streaming, Corresponding structure pstInParam = NET_IN_RTMP_MANAGER_STOP, pstOutParam = NET_OUT_RTMP_MANAGER_STOP;
    NET_EM_RTMP_MANAGER_OPER_TYPE_PAUSE = 5,    # 暂停推流，只对回放流有效, 对应结构体 pstInparam = NET_IN_RTMP_MANAGER_PAUSE, pstOutParam = NET_OUT_RTMP_MANAGER_PAUSE;Pause streaming, which is only valid for playback streams, Corresponding structure pstInparam = NET_IN_RTMP_MANAGER_PAUSE, pstOutParam = NET_OUT_RTMP_MANAGER_PAUSE;
    NET_EM_RTMP_MANAGER_OPER_TYPE_RESUME = 6,   # 恢复推流，只对回放流有效, 对应结构体 pstInparam = NET_IN_RTMP_MANAGER_RESUME, pstOutParam = NET_OUT_RTMP_MANAGER_RESUME;Resume streaming, which is only valid for playback streams, Corresponding structure pstInparam = NET_IN_RTMP_MANAGER_RESUME, pstOutParam = NET_OUT_RTMP_MANAGER_RESUME;
    NET_EM_RTMP_MANAGER_OPER_TYPE_SET_SPEED = 7,    # 设置倍速推流，只对回放流有效, 对应结构体 pstInparam = NET_IN_RTMP_MANAGER_SET_SPEED, pstOutParam = NET_OUT_RTMP_MANAGER_SET_SPEED;Set the double speed push stream, which is only valid for playback stream, Corresponding structure pstInparam = NET_IN_RTMP_MANAGER_SET_SPEED, pstOutParam = NET_OUT_RTMP_MANAGER_SET_SPEED;

class EM_A_NET_EM_RTMP_MANAGER_ADD_TYPE(IntEnum):
    """
    添加推流地址类型
    Add streaming address type
    """
    NET_EM_RTMP_MANAGER_ADD_TYPE_UNKNOWN = -1,  # 未知;unknown;
    NET_EM_RTMP_MANAGER_ADD_TYPE_LIVE_STREAM = 0,    # 实时流;Live Stream;
    NET_EM_RTMP_MANAGER_ADD_TYPE_RECORD_STREAM = 1,    # 回放流;Record stream;

class EM_SNAP_ENCODE_TYPE(IntEnum):
    """
    抓图图片编码格式
    Picture encoding format
    """
    EM_SNAP_ENCODE_TYPE_UNKNOWN = 0,            # 未知;Unknwon;
    EM_SNAP_ENCODE_TYPE_JPEG = 1,               # jpeg图片;Jpeg;
    EM_SNAP_ENCODE_TYPE_MPEG4_I = 2,            # mpeg4的i 帧;I frame of MPEG4;

class EM_GROUP_TYPE(IntEnum):
    """
    Onvif 用户所在组
    Onvif User Group
    """
    EM_GROUP_TYPE_UNKNOWN = 0,                  # UnKnown;UnKnown;
    EM_GROUP_TYPE_ADMIN = 1,                    # admin;admin;
    EM_GROUP_TYPE_OPERATOR = 2,                 # operator;operator;
    EM_GROUP_TYPE_USER = 3,                     # user;user;
    EM_GROUP_TYPE_ANONYMOUS = 4,                # anonymous;anonymous;

class EM_UPGRADE_TYPE(IntEnum):
    """
    升级类型
    Upgrade type
    """
    EM_A_UPGRADE_BIOS_TYPE = 1,                 # BIOS升级;BIOS upgrade;
    EM_A_UPGRADE_WEB_TYPE = 2,                  # WEB升级;WEB upgrade;
    EM_A_UPGRADE_BOOT_YPE = 3,                  # BOOT升级;BOOT upgrade;
    EM_A_UPGRADE_CHARACTER_TYPE = 4,            # 汉字库;Chinese character library;
    EM_A_UPGRADE_LOGO_TYPE = 5,                 # LOGO;LOGO;
    EM_A_UPGRADE_EXE_TYPE = 6,                  # EXE,例如播放器等;EXE such as player;
    EM_A_UPGRADE_DEVCONSTINFO_TYPE = 7,         # 设备固有信息设置(如：硬件ID,MAC,序列号);upgrade device information;
    EM_A_UPGRADE_PERIPHERAL_TYPE = 8,           # 外设接入从片(如车载287芯片);Peripheral access from (such as car 287 chip);
    EM_A_UPGRADE_GEOINFO_TYPE = 9,              # 地理信息定位芯片;Geographic information positioning chip;
    EM_A_UPGRADE_MENU = 10,                     # 菜单（设备操作界面的图片）;Menu (equipment operation interface of the picture);
    EM_A_UPGRADE_ROUTE = 11,                    # 线路文件（如公交线路）;Line files (such as bus lines);
    EM_A_UPGRADE_ROUTE_STATE_AUTO = 12,         # 报站音频（与线路配套的报站音频）;Stops the audio (with line stops audio);
    EM_A_UPGRADE_SCREEN = 13,                   # 调度屏（如公交操作屏）;Scheduling screen (e.g., bus operation panel);

class EM_OPERATE_USER_TYPE(IntEnum):
    """
    用户操作类型
    user operate type
    """
    EM_OPERATE_USER_GROUP_ADD = 0,              # 增加用户组, 对应opParam=NET_A_USER_GROUP_INFO_EX, subParam=None; To add a user group, opParam=NET_A_USER_GROUP_INFO_EX, subParam=None
    EM_OPERATE_USER_GROUP_DELETE = 1,           # 删除用户组, 对应opParam=NET_A_USER_GROUP_INFO_EX, subParam=None; To delete a user group, opParam=NET_A_USER_GROUP_INFO_EX, subParam=None
    EM_OPERATE_USER_GROUP_MODIFY = 2,           # 修改用户组, 对应opParam=NET_A_USER_GROUP_INFO_EX, subParam=NET_A_USER_GROUP_INFO_EX; To modify a user group, opParam=NET_A_USER_GROUP_INFO_EX, subParam=NET_A_USER_GROUP_INFO_EX
    EM_OPERATE_USER_ADD = 3,                    # 增加用户, 对应opParam=NET_A_USER_INFO_EX, subParam=None; To add a user, opParam=NET_A_USER_INFO_EX, subParam=None
    EM_OPERATE_USER_DELETE = 4,                 # 删除用户, 对应opParam=NET_A_USER_INFO_EX, subParam=None; To delete a user, opParam=NET_A_USER_INFO_EX, subParam=None
    EM_OPERATE_USER_MODIFY = 5,                 # 修改用户, 对应opParam=NET_A_USER_INFO_EX, subParam=NET_A_USER_INFO_EX; To modify a user, opParam=NET_A_USER_INFO_EX, subParam=NET_A_USER_INFO_EX
    EM_OPERATE_USER_PASSWORD_MODIFY = 6,        # 修改用户密码, 对应opParam=NET_A_USER_INFO_EX, subParam=NET_A_USER_INFO_EX; To modify a user password, opParam=NET_A_USER_INFO_EX, subParam=NET_A_USER_INFO_EX

class EM_OPERATE_USER_NEW_TYPE(IntEnum):
    """
    用户操作类型-新
    user operate type - new
    """
    EM_NEW_OPERATE_USER_GROUP_ADD = 0,          # 增加用户组, 对应opParam=NET_A_USER_GROUP_INFO_NEW, subParam=None; To add a user group, opParam=NET_A_USER_GROUP_INFO_NEW, subParam=None
    EM_NEW_OPERATE_USER_GROUP_DELETE = 1,       # 删除用户组, 对应opParam=NET_A_USER_GROUP_INFO_NEW, subParam=None; To delete a user group, opParam=NET_A_USER_GROUP_INFO_NEW, subParam=None
    EM_NEW_OPERATE_USER_GROUP_MODIFY = 2,       # 修改用户组, 对应opParam=NET_A_USER_GROUP_INFO_NEW, subParam=NET_A_USER_GROUP_INFO_NEW; To modify a user group, opParam=NET_A_USER_GROUP_INFO_NEW, subParam=NET_A_USER_GROUP_INFO_NEW
    EM_NEW_OPERATE_USER_ADD = 3,                # 增加用户, 对应opParam=NET_A_USER_INFO_NEW, subParam=None; To add a user, opParam=NET_A_USER_INFO_NEW, subParam=None
    EM_NEW_OPERATE_USER_DELETE = 4,             # 删除用户, 对应opParam=NET_A_USER_INFO_NEW, subParam=None; To delete a user, opParam=NET_A_USER_INFO_NEW, subParam=None
    EM_NEW_OPERATE_USER_MODIFY = 5,             # 修改用户, 对应opParam=NET_A_USER_INFO_NEW, subParam=NET_A_USER_INFO_NEW; To modify a user, opParam=NET_A_USER_INFO_NEW, subParam=NET_A_USER_INFO_NEW
    EM_NEW_OPERATE_USER_PASSWORD_MODIFY = 6,    # 修改用户密码, 对应opParam=NET_A_USER_INFO_NEW, subParam=NET_A_USER_INFO_NEW; To modify a user password, opParam=NET_A_USER_INFO_NEW, subParam=NET_A_USER_INFO_NEW

class EM_A_NET_EM_RTMP_MANAGER_STREAM_TYPE(IntEnum):
    """
    码流类型
    Bitstream type
    """
    NET_EM_RTMP_MANAGER_STREAM_TYPE_UNKNOWN = -1,    # 未知;unknown;
    NET_EM_RTMP_MANAGER_STREAM_TYPE_MAINCODE_STREAM = 0,    # 主码流;maincode stream;
    NET_EM_RTMP_MANAGER_STREAM_TYPE_SECONDARYCODE_STREAM1 = 1,    # 辅码流1;Auxiliary code stream1;
    NET_EM_RTMP_MANAGER_STREAM_TYPE_SECONDARYCODE_STREAM2 = 2,    # 辅码流2;Auxiliary code stream2;

class EM_A_NET_EM_RTMP_MANAGER_ADD_ERRCODE(IntEnum):
    """
    Add 表示错误码
    Add Indicates the error code
    """
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_UNKNOWN = -1,    # 未知;unknown;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_NOERROR = 0,    # 无错误;no error;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_LIVECHANNEL_NOT_ONLINE = 1,    # 实时流通道不在线;Real time channel not online;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_RECORDVIDEO_NOT_FOUND = 2,    # 回放流录像查不到;Playback stream video not found;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_EXCEED_MAX_LIVECHANNEL = 3,    # 超过最大实时流推流通道限制;Maximum real-time streaming channel limit exceeded;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_EXCEED_MAX_RECORDCHANNEL = 4,    # 超过最大回放流推流通道限制;Maximum playback stream push channel limit exceeded;
    NET_EM_RTMP_MANAGER_ADD_ERRCODE_OTHER_ERRORS = 5,    # 其他错误;other error;

class EM_SCREEN_TEXT_TYPE(IntEnum):
    """
    屏幕文本类型
    Screen text type
    """
    EM_SCREEN_TEXT_TYPE_UNKNOWN = -1,           # 未知;Unknown;
    EM_SCREEN_TEXT_TYPE_ORDINARY = 0,           # 普通;Ordinary;
    EM_SCREEN_TEXT_TYPE_LOCAL_TIME = 1,         # 本地时间;Local time;
    EM_SCREEN_TEXT_TYPE_QR_CODE = 2,            # 二维码;Qr code;
    EM_SCREEN_TEXT_TYPE_RESOURCE = 3,           # 资源文件;RESOURCE;

class EM_SCREEN_TEXT_COLOR(IntEnum):
    """
    屏幕文本颜色
    Screen text color
    """
    EM_SCREEN_TEXT_COLOR_UNKNOWN = -1,          # 未知;Unknown;
    EM_SCREEN_TEXT_COLOR_GREEN = 0,             # 绿色;Green;
    EM_SCREEN_TEXT_COLOR_RED = 1,               # 红色;Red;
    EM_SCREEN_TEXT_COLOR_YELLOW = 2,            # 黄色;Yellow;
    EM_SCREEN_TEXT_COLOR_WHITE = 3,             # 白色;White;

class EM_SCREEN_TEXT_ROLL_MODE(IntEnum):
    """
    屏幕文本滚动模式
    Screen text roll mode
    """
    EM_SCREEN_TEXT_ROLL_MODE_UNKNOWN = -1,      # 未知;Unknown;
    EM_SCREEN_TEXT_ROLL_MODE_NO = 0,            # 不滚动;No scrolling;
    EM_SCREEN_TEXT_ROLL_MODE_LEFT_RIGHT = 1,    # 左右滚动;Scroll left and right;
    EM_SCREEN_TEXT_ROLL_MODE_UP_DOWN = 2,       # 上下翻页滚动;Page up and down;

class EM_BROADCAST_TEXT_TYPE(IntEnum):
    """
    播报文本类型
    Broadcast text type
    """
    EM_BROADCAST_TEXT_TYPE_UNKNOWN = -1,        # 未知;Unknown;
    EM_BROADCAST_TEXT_TYPE_ORDINARY = 0,        # 普通;Ordinary;
    EM_BROADCAST_TEXT_TYPE_PLATE_NUMBER = 1,    # 车牌号;Plate number;
    EM_BROADCAST_TEXT_TYPE_TIME = 2,            # 时间;Time;
    EM_BROADCAST_TEXT_TYPE_NUMBER_STRING = 3,   # 数字字符串;Number string;

class EM_CARPASS_STATUS(IntEnum):
    """
    过车状态
    car pass status
    """
    EM_CARPASS_STATUS_UNKNOWN = 0,              # 未知状态;Unknown status;
    EM_CARPASS_STATUS_CARPASS = 1,              # 过车状态;car pass status;
    EM_CARPASS_STATUS_NORMAL = 2,               # 无车状态;no car status;

class EM_EXCEPTION_TYPE(IntEnum):
    """
    异常事件类型
    Exception type
    """
    EM_EXCEPTION_KNOWN = 0,                     # 未知类型;Unknown;
    EM_EXCEPTION_NOTALLOWED_IPLOGIN = 1,        # 不被允许的IP访问设备;IP access device not allowed;
    EM_EXCEPTION_NOTALLOWED_TIMELOGIN = 2,      # 账户在非允许时间范围内发起登录;The account initiates a login within the non-allowed time frame;
    EM_EXCEPTION_URLERROR_OVERLIMIT = 3,        # Web路径爆破行为;Web path blasting behavior;
    EM_EXCEPTION_SESSIONNUM_OVERLIMIT = 4,      # 会话连接数超限;The number of session connections exceeds the limit;
    EM_EXCEPTION_SESSIONID_ERROR_OVERLIMIT = 5, # 会话ID爆破行为;Session ID blasting behavior;
    EM_EXCEPTION_FDEXHAUSTION = 6,              # 网络连接资源被耗尽;Network connection resources are exhausted;
    EM_EXCEPTION_EXCEPTIONPROGRAMRUN = 7,       # 可信环境监测到异常程序运行;Trusted environment detects abnormal program operation;
    EM_EXCEPTION_ACCOUNTORPWDERROROVERLIMIT = 8,    # 用户名密码爆破行为;User name password blasting;
    EM_EXCEPTION_ROOTKIT_DETECTION = 9,         # Rootkit检测;RootKit Detection;
    EM_EXCEPTION_HIDE_PROCESS_DETECTION = 10,   # 隐藏进程检测;Hide Process Detection;

class EM_A_NET_ACCESSCTLCARD_AUTHORITY(IntEnum):
    """
    用户权限
    user authority
    """
    NET_ACCESSCTLCARD_AUTHORITY_UNKNOWN = 0,    # 未知;unknown;
    NET_ACCESSCTLCARD_AUTHORITY_ADMINISTRATORS = 1,    # 管理员;administrator;
    NET_ACCESSCTLCARD_AUTHORITY_CUSTOMER = 2,   # 普通用户;customer;

class EM_GREENCNHEALTH_STATUS(IntEnum):
    """
    人员健康状态
    Health status of personnel
    """
    EM_GREENCNHEALTH_STATUS_UNKNOWN = 0,        # 未知;unknown;
    EM_GREENCNHEALTH_STATUS_GREEN = 1,          # 绿码;green (health) code;
    EM_GREENCNHEALTH_STATUS_YELLOW = 2,         # 黄码;Yellow code;
    EM_GREENCNHEALTH_STATUS_RED = 3,            # 红码;The red code;
    EM_GREENCNHEALTH_STATUS_INVALID = 4,        # 无效;invalid;

class EM_ALLOW_PERMIT_FLAG(IntEnum):
    """
    电子通行证状态
    E-pass Status 
    """
    EM_ALLOW_PERMIT_FLAG_UNKNOWN = 0,           # 未知;unknown;
    EM_ALLOW_PERMIT_FLAG_NO = 1,                # 没有电子通行证;No e-pass;
    EM_ALLOW_PERMIT_FLAG_EFFECTIVE = 2,         # 电子通行证有效;E-pass valid;
    EM_ALLOW_PERMIT_FLAG_INVALID = 3,           # 电子通行证无效;E-pass invalid;

class EM_RENT_STATE(IntEnum):
    """
    对接第三方平台数据
    Connect to third-party platform data
    """
    EM_RENT_STATE_UNKNOWN = 0,                  # 未知;Unknown;
    EM_RENT_STATE_NORMAL_PAYMENT = 1,           # 正常缴费;Normal payment;
    EM_RENT_STATE_0_TO_3_MONTHS_IN_ARREARS = 2, # 欠费0~3个月;0~3 months in arrears;
    EM_RENT_STATE_3_TO_6_MONTHS_IN_ARREARS = 3, # 欠费3~6个月;3~6 months in arrears;
    EM_RENT_STATE_6_TO_12_MONTHS_IN_ARREARS = 4,    # 欠费6~12个月;6~12 months in arrears;
    EM_RENT_STATE_MORE_THAN_12_MONTHS_IN_ARREARS = 5,    # 欠费12个月以上;More than 12 months in arrears;
    EM_RENT_STATE_TEMPORARY_VISITOR = 6,        # 临时访客;Temporary visitor;

class EM_OPEN_DOOR_TYPE(IntEnum):
    """
    门禁控制--开门方式
    Access controller -- Open door type
    """
    EM_OPEN_DOOR_TYPE_UNKNOWN = 0,
    EM_OPEN_DOOR_TYPE_REMOTE = 1,               # 远程开门;Remote;
    EM_OPEN_DOOR_TYPE_LOCAL_PASSWORD = 2,       # 本地密码开门;Local_Password;
    EM_OPEN_DOOR_TYPE_LOCAL_CARD = 3,           # 本地刷卡开门;Local_Card;
    EM_OPEN_DOOR_TYPE_LOCAL_BUTTON = 4,         # 本地按钮开门;Local_Button;

class EM_OPEN_DOOR_DIRECTION(IntEnum):
    """
    开门方向
    open door direction
    """
    EM_OPEN_DOOR_DIRECTION_UNKNOWN = 0,         # 未知，设备自行决定;unknown, device control;
    EM_OPEN_DOOR_DIRECTION_FROM_ENTER = 1,      # 朝进门方向开门;open from enter direction;
    EM_OPEN_DOOR_DIRECTION_FROM_LEAVE = 2,      # 朝出门方向开门;open from enter direction;

class EM_REMOTE_CHECK_CODE(IntEnum):
    """
    远程权限验证结果
    remote check code
    """
    EM_REMOTE_CHECK_CODE_UNKNOWN = -1,          # 未知;unknown;
    EM_REMOTE_CHECK_CODE_SUCCESS = 0,           # 成功;success;
    EM_REMOTE_CHECK_CODE_FAIL = 1,              # 失败;fail;

class EM_A_NET_EM_ACCESS_CTL_USER_SERVICE(IntEnum):
    """
    人员信息操作类型
    operate type of userinfo
    """
    NET_EM_ACCESS_CTL_USER_SERVICE_INSERT = 0,  # 添加人员信息, pstInParam = NET_IN_ACCESS_USER_SERVICE_INSERT , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_INSERT;insert user info, pstInParam = NET_IN_ACCESS_USER_SERVICE_INSERT , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_INSERT;
    NET_EM_ACCESS_CTL_USER_SERVICE_GET = 1,     # 获取人员信息, pstInParam = NET_IN_ACCESS_USER_SERVICE_GET , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_GET;get user info, pstInParam = NET_IN_ACCESS_USER_SERVICE_GET , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_GET;
    NET_EM_ACCESS_CTL_USER_SERVICE_REMOVE = 2,  # 删除人员信息,包含所有授权信息 pstInParam = NET_IN_ACCESS_USER_SERVICE_REMOVE , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_REMOVE;delete user info, pstInParam = NET_IN_ACCESS_USER_SERVICE_REMOVE , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_REMOVE;
    NET_EM_ACCESS_CTL_USER_SERVICE_CLEAR = 3,   # 清空所有人员信息, pstInParam = NET_IN_ACCESS_USER_SERVICE_CLEAR , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_CLEAR;clear user info, pstInParam = NET_IN_ACCESS_USER_SERVICE_CLEAR , pstOutParam = NET_OUT_ACCESS_USER_SERVICE_CLEAR;

class EM_A_NET_ENUM_USER_TYPE(IntEnum):
    """
    用户类型
    user type
    """
    NET_ENUM_USER_TYPE_UNKNOWN = -1,            # 未知用户;unknown;
    NET_ENUM_USER_TYPE_NORMAL = 0,              # 普通用户;normal;
    NET_ENUM_USER_TYPE_BLACKLIST = 1,           # 禁止名单用户;blocklist;
    NET_ENUM_USER_TYPE_GUEST = 2,               # 来宾账户;guset;
    NET_ENUM_USER_TYPE_PATROL = 3,              # 巡逻用户;patrol;
    NET_ENUM_USER_TYPE_VIP = 4,
    NET_ENUM_USER_TYPE_HANDICAP = 5,            # 残障用户;handicap;
    NET_ENUM_USER_TYPE_CUSTOM1 = 6,             # 自定义用户1; user1;
    NET_ENUM_USER_TYPE_CUSTOM2 = 7,             # 自定义用户2; user2;

class EM_A_NET_ATTENDANCE_AUTHORITY(IntEnum):
    """
    用户权限
    authority
    """
    NET_ATTENDANCE_AUTHORITY_UNKNOWN = -1,
    NET_ATTENDANCE_AUTHORITY_CUSTOMER = 0,      # 普通用户;customer;
    NET_ATTENDANCE_AUTHORITY_ADMINISTRATORS = 1,    # 管理员;administrators;

class EM_TYPE_OF_CERTIFICATE(IntEnum):
    """
    证件类型
    type of certificate
    """
    EM_TYPE_OF_CERTIFICATE_UNKNOWN = 0,         # 未知;unknown;
    EM_TYPE_OF_CERTIFICATE_IDCARD = 1,          # 证件;ID card;
    EM_TYPE_OF_CERTIFICATE_HKMRPERMIT = 2,      # 港澳居住证;Hong Kong and Macau Residence Permit;
    EM_TYPE_OF_CERTIFICATE_CHNPASSPORT = 3,     # 中国护照;Chinese passport;
    EM_TYPE_OF_CERTIFICATE_FORPASSPORT = 4,     # 国外护照;Foreign passport;
    EM_TYPE_OF_CERTIFICATE_PERRESIDENCE_PERMI = 5,    # 永久居住证;Permanent residence permit;
    EM_TYPE_OF_CERTIFICATE_OTHER = 9,           # 其他;Other;

class EM_A_NET_EM_FAILCODE(IntEnum):
    """
    操作错误码
    error code
    """
    NET_EM_FAILCODE_NOERROR = 0,                # 没有错误;no error;
    NET_EM_FAILCODE_UNKNOWN = 1,                # 未知错误;unknown;
    NET_EM_FAILCODE_INVALID_PARAM = 2,          # 参数错误;invalid param;
    NET_EM_FAILCODE_INVALID_PASSWORD = 3,       # 无效密码;invalid password;
    NET_EM_FAILCODE_INVALID_FP = 4,             # 无效数据;invalid fingprint;
    NET_EM_FAILCODE_INVALID_FACE = 5,           # 无效人脸数据;invalid face date;
    NET_EM_FAILCODE_INVALID_CARD = 6,           # 无效卡数据;invalid card date;
    NET_EM_FAILCODE_INVALID_USER = 7,           # 无效人数据;invalid user date;
    NET_EM_FAILCODE_FAILED_GET_SUBSERVICE = 8,  # 能力集子服务获取失败;get sub services failed;
    NET_EM_FAILCODE_FAILED_GET_METHOD = 9,      # 获取组件的方法集失败;get method failed;
    NET_EM_FAILCODE_FAILED_GET_SUBCAPS = 10,    # 获取资源实体能力集失败;get subcaps failed;
    NET_EM_FAILCODE_ERROR_INSERT_LIMIT = 11,    # 已达插入上限;insert limit;
    NET_EM_FAILCODE_ERROR_MAX_INSERT_RATE = 12, # 已达最大插入速度;max insert rate;
    NET_EM_FAILCODE_FAILED_ERASE_FP = 13,       # 清除数据失败;erase fingprint date failed;
    NET_EM_FAILCODE_FAILED_ERASE_FACE = 14,     # 清除人脸数据失败;erase face datefailed;
    NET_EM_FAILCODE_FAILED_ERASE_CARD = 15,     # 清除卡数据失败;erase card date failed;
    NET_EM_FAILCODE_NO_RECORD = 16,             # 没有记录;no record;
    NET_EM_FAILCODE_NOMORE_RECORD = 17,         # 查找到最后，没有更多记录;no more record;
    NET_EM_FAILCODE_RECORD_ALREADY_EXISTS = 18, # 下发卡或时，数据重复;record already;
    NET_EM_FAILCODE_MAX_FP_PERUSER = 19,        # 超过个人最大记录数;max fingprint per user;
    NET_EM_FAILCODE_MAX_CARD_PERUSER = 20,      # 超过个人最大卡片记录数;max card per user;
    NET_EM_FAILCODE_EXCEED_MAX_PHOTOSIZE = 21,  # 超出最大照片大小;exceed max picture size;
    NET_EM_FAILCODE_INVALID_USERID = 22,        # 用户ID无效（未找到客户）;invalid user id(not found user);
    NET_EM_FAILCODE_EXTRACTFEATURE_FAIL = 23,   # 提取人脸特征失败;extract face feature fail;
    NET_EM_FAILCODE_PHOTO_EXIST = 24,           # 人脸照片已存在;photo already exist;
    NET_EM_FAILCODE_PHOTO_OVERFLOW = 25,        # 超出最大人脸照片数;exceed max photos;
    NET_EM_FAILCODE_INVALID_PHOTO_FORMAT = 26,  # 照片格式无效;invalid photo format;
    NET_EM_FAILCODE_EXCEED_ADMINISTRATOR_LIMIT = 27,    # 超出管理员人数限制;exceed administrator limit;
    NET_EM_FAILECODE_FACE_FEATURE_ALREADY_EXIST = 28,    # 人脸特征已存在;Facial features already exist;
    NET_EM_FAILECODE_FINGERPRINT_EXIST = 29,    # 已存在;Fingprint already exist;
    NET_EM_FAILECODE_CITIZENID_EXIST = 30,      # 证件号已存在;CitizenID already exist;
    NET_EM_FAILECODE_NORMAL_USER_NOTSUPPORT = 31,    # 不支持普通用户下发;Ordinary users do not support delivery;
    NET_EM_FAILCODE_NO_FACE_DETECTED = 32,      # 图片中检测到0个人脸目标;0 face targets detected in the picture;
    NET_EM_FAILCODE_MULTI_FACE_DETECTED = 33,   # 图片中检测到多个人脸，无法返回特征;Multiple faces are detected in the picture, and features cannot be returned;
    NET_EM_FAILCODE_PICTURE_DECODING_ERROR = 34,    # 图片解码错误;Picture decoding error;
    NET_EM_FAILCODE_LOW_PICTURE_QUALITY = 35,   # 图片质量太低;Picture quality is too low;
    NET_EM_FAILCODE_NOT_RECOMMENDED = 36,       # 结果不推荐使用，比如：对外国人，特征提取成功，但算法支持不好，容易造成误识别;The result is not recommended, for example: for foreigners, the feature extraction is successful, but the algorithm support is not good, and it is easy to cause misidentification;
    NET_EM_FAILCODE_FACE_ANGLE_OVER_THRESHOLDS = 37,    # 人脸角度超过配置阈值;The face angle exceeds the configured threshold;
    NET_EM_FAILCODE_FACE_RADIO_EXCEEDS_RANGE = 38,    # 人脸占比超出范围，算法建议占比:不要超过2/3;不要小于1/3;The proportion of the face is out of range, the algorithm recommends the proportion: no more than 2/3; no less than 1/3;
    NET_EM_FAILCODE_FACE_OVER_EXPOSED = 39,     # 人脸过爆;Overburdened face;
    NET_EM_FAILCODE_FACE_UNDER_EXPOSED = 40,    # 人脸欠爆;Face undershot;
    NET_EM_FAILCODE_BRIGHTNESS_IMBALANCE = 41,  # 人脸亮度不均衡 ,用于判断阴阳脸;Unbalanced face brightness, used to judge yin and yang faces;
    NET_EM_FAILCODE_FACE_LOWER_CONFIDENCE = 42, # 人脸的置信度低;Facial confidence is low;
    NET_EM_FAILCODE_FACE_LOW_ALIGN = 43,        # 人脸对齐分数低;Low face alignment score;
    NET_EM_FAILCODE_FRAGMENTARY_FACE_DETECTED = 44,    # 人脸存在遮挡、残缺不全;The face is blocked or incomplete;
    NET_EM_FAILCODE_PUPIL_DISTANCE_NOT_ENOUGH = 45,    # 人脸瞳距小于阈值;Face pupil distance is less than the threshold;
    NET_EM_FAILCODE_FACE_DATA_DOWNLOAD_FAILED = 46,    # 人脸数据下载失败;Face data download failed;
    NET_EM_FAILCODE_FACE_FFE_FAILED = 47,       # 人脸可检测，但特征值提取失败（算法场景）;The face can be detected, but the feature value extraction fails (algorithm scene);
    NET_EM_FAILCODE_PHOTO_FEATURE_FAILED_FOR_FA = 48,    # 人脸照片因口罩，帽子，墨镜等人脸属性不符合而提取特征值错误;The feature value extracted from the face photo is incorrect due to the inconsistency of face attributes such as masks, hats, sunglasses, etc.;
    NET_EM_FAILCODE_FACE_DATA_PHOTO_INCOMPLETE = 49,    # 人脸照片不完整;Incomplete face photo;
    NET_EM_FAILCODE_DATABASE_ERROR_INSERT_OVERFLOW = 50,    # 数据库插入越上限;Database error insert overflow;
    NET_EM_CARD_NOT_EXIST = 51,                 # 卡号不存在;Card not exist;
    NET_EM_FAILCODE_USER_EXIST = 52,            # User已存在;User Already Exist;
    NET_EM_FAILCODE_CARD_NUM_EXIST = 53,        # 卡号已存在;Card Already Exist;
    NET_EM_FAILCODE_FINGERPRINT_DOWNLOAD_FAIL = 54,    # 通过URL下载方式下载失败; Download Fail;
    NET_EM_FAILCODE_ACCOUNT_IN_USE = 55,        # 账户登录中;Account In Use;
    NET_EM_FAILCODE_IRIS_INFO_NOT_EXISTED = 56, # 更新用户目标信息时,用户不存在目标;Iris Info Not Existed;
    NET_EM_FAILCODE_INVALID_IRIS_DATA = 57,     # 下发的目标数据格式、特征值大小错误;Invalid Iris Data;
    NET_EM_FAILCODE_IRIS_ALREADY_EXIST = 58,    # 目标已存在;Iris Already Exist;
    NET_EM_FAILCODE_ERASE_IRIS_FAILED = 59,     # 目标信息删除失败;Erase Iris Failed;
    NET_EM_FAILCODE_EXCEED_MAX_IRIS_GROUP_COUNT_PER_USER = 60,    # 超出个人所支持的目标组数量，两个目标(左右眼)为一组;Exceed Max Iris Group Count Per User;
    NET_EM_FAILCODE_EXCEED_MAX_IRIS_COUNT_PER_GROUP = 61,    # 超出个人单组目标所能记录的最大数量;Exceed Max Iris Count Per Group;

class EM_A_NET_EM_ACCESS_CTL_FACE_SERVICE(IntEnum):
    """
    人脸信息操作类型
    the operate type of face info
    """
    NET_EM_ACCESS_CTL_FACE_SERVICE_INSERT = 0,  # 添加, pInbuf = NET_IN_ACCESS_FACE_SERVICE_INSERT , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_INSERT;insert, pInbuf = NET_IN_ACCESS_FACE_SERVICE_INSERT , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_INSERT;
    NET_EM_ACCESS_CTL_FACE_SERVICE_GET = 1,     # 获取, pInbuf = NET_IN_ACCESS_FACE_SERVICE_GET , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_GET;get, pInbuf = NET_IN_ACCESS_FACE_SERVICE_GET , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_GET;
    NET_EM_ACCESS_CTL_FACE_SERVICE_UPDATE = 2,  # 更新, pInbuf = NET_IN_ACCESS_FACE_SERVICE_UPDATE , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_UPDATE;update, pInbuf = NET_IN_ACCESS_FACE_SERVICE_UPDATE , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_UPDATE;
    NET_EM_ACCESS_CTL_FACE_SERVICE_REMOVE = 3,  # 删除, pInbuf = NET_IN_ACCESS_FACE_SERVICE_REMOVE , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_REMOVE;remove, pInbuf = NET_IN_ACCESS_FACE_SERVICE_REMOVE , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_REMOVE;
    NET_EM_ACCESS_CTL_FACE_SERVICE_CLEAR = 4,   # 清空, pInbuf = NET_IN_ACCESS_FACE_SERVICE_CLEAR , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_CLEAR;clear, pInbuf = NET_IN_ACCESS_FACE_SERVICE_CLEAR , pOutBuf = NET_OUT_ACCESS_FACE_SERVICE_CLEAR;

class EM_A_NET_EM_ACCESS_CTL_CARD_SERVICE(IntEnum):
    """
    卡片信息操作类型
    type of operate card
    """
    NET_EM_ACCESS_CTL_CARD_SERVICE_INSERT = 0,  # 添加, pstInParam = NET_IN_ACCESS_CARD_SERVICE_INSERT , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_INSERT;insert, pstInParam = NET_IN_ACCESS_CARD_SERVICE_INSERT , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_INSERT;
    NET_EM_ACCESS_CTL_CARD_SERVICE_GET = 1,     # 获取, pstInParam = NET_IN_ACCESS_CARD_SERVICE_GET , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_GET;get, pstInParam = NET_IN_ACCESS_CARD_SERVICE_GET , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_GET;
    NET_EM_ACCESS_CTL_CARD_SERVICE_UPDATE = 2,  # 更新, pstInParam = NET_IN_ACCESS_CARD_SERVICE_UPDATE , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_UPDATE;update, pstInParam = NET_IN_ACCESS_CARD_SERVICE_UPDATE , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_UPDATE;
    NET_EM_ACCESS_CTL_CARD_SERVICE_REMOVE = 3,  # 删除, pstInParam = NET_IN_ACCESS_CARD_SERVICE_REMOVE , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_REMOVE;remove, pstInParam = NET_IN_ACCESS_CARD_SERVICE_REMOVE , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_REMOVE;
    NET_EM_ACCESS_CTL_CARD_SERVICE_CLEAR = 4,   # 清空, pstInParam = NET_IN_ACCESS_CARD_SERVICE_CLEAR , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_CLEAR;clear, pstInParam = NET_IN_ACCESS_CARD_SERVICE_CLEAR , pstOutParam = NET_OUT_ACCESS_CARD_SERVICE_CLEAR;

class EM_A_NET_SENSE_METHOD(IntEnum):
    """
    传感器感应方式枚举类型
    Sensor's Sense Method Enumeration Type
    """
    NET_SENSE_UNKNOWN = -1,                     # 未知类型;Unknowed type;
    NET_SENSE_DOOR = 0,                         # 门磁;Door Contact;
    NET_SENSE_PASSIVEINFRA = 1,                 # 被动红外;Passive Infrared;
    NET_SENSE_GAS = 2,                          # 气感;Gase Induce);
    NET_SENSE_SMOKING = 3,                      # 烟感;Smoking Induce;
    NET_SENSE_WATER = 4,                        # 水感;Wwater Induce);
    NET_SENSE_ACTIVEFRA = 5,                    # 主动红外;Initiative Infrared;
    NET_SENSE_GLASS = 6,                        # 玻璃破碎;Glass Broken;
    NET_SENSE_EMERGENCYSWITCH = 7,              # 紧急开关;Emergency switch;
    NET_SENSE_SHOCK = 8,                        # 震动;Shock;
    NET_SENSE_DOUBLEMETHOD = 9,                 # 双鉴(红外+微波);Double Method(Infrare+Microwave);
    NET_SENSE_THREEMETHOD = 10,                 # 三技术;Three Method;
    NET_SENSE_TEMP = 11,                        # 温度;Temperature;
    NET_SENSE_HUMIDITY = 12,                    # 湿度;Humidity;
    NET_SENSE_WIND = 13,                        # 风速;Wind;
    NET_SENSE_CALLBUTTON = 14,                  # 呼叫按钮;Call button;
    NET_SENSE_GASPRESSURE = 15,                 # 气体压力;Gas Pressure;
    NET_SENSE_GASCONCENTRATION = 16,            # 燃气浓度;Gas Concentration;
    NET_SENSE_GASFLOW = 17,                     # 气体流量;Gas Flow;
    NET_SENSE_OTHER = 18,                       # 其他;Other;
    NET_SENSE_OIL = 19,                         # 油量检测,汽油、柴油等车辆用油检测;oil detection, gasoline, diesel vehicles detection;
    NET_SENSE_MILEAGE = 20,                     # 里程数检测;mileage detection;
    NET_SENSE_URGENCYBUTTON = 21,               # 紧急按钮;Urgency button;
    NET_SENSE_STEAL = 22,                       # 盗窃;Steal;
    NET_SENSE_PERIMETER = 23,                   # 周界;Permeter;
    NET_SENSE_PREVENTREMOVE = 24,               # 防拆;Prevent remove;
    NET_SENSE_DOORBELL = 25,                    # 门铃;Door bell;
    NET_SENSE_ALTERVOLT = 26,                   # 交流电压传感器;Alter voltage sensor;
    NET_SENSE_DIRECTVOLT = 27,                  # 直流电压传感器;Direct voltage sensor;
    NET_SENSE_ALTERCUR = 28,                    # 交流电流传感器;Alter current sensor;
    NET_SENSE_DIRECTCUR = 29,                   # 直流电流传感器;Direct current sensor;
    NET_SENSE_RSUGENERAL = 30,                  # 通用模拟量 4~20mA或0~5V;RSU general analog sensor, 4~20mA or 0~5V;
    NET_SENSE_RSUDOOR = 31,                     # 门禁感应;RSU door sensor;
    NET_SENSE_RSUPOWEROFF = 32,                 # 高新兴断电感应;RSU power off sensor;
    NET_SENSE_TEMP1500 = 33,                    # 1500温度传感器;1500 temperature sensor;
    NET_SENSE_TEMPDS18B20 = 34,                 # DS18B20温度传感器;DS18B20 temperature sensor;
    NET_SENSE_HUMIDITY1500 = 35,                # 1500湿度传感器;1500 humidity sensor;
    NET_SENSE_INFRARED = 36,                    # 红外报警;Infrared sensor;
    NET_SENSE_FIREALARM = 37,                   # 火警;firealarm sensor;
    NET_SENSE_CO2 = 38,                         # CO2浓度检测,典型值:0~5000ppm;Determination of CO2, typical value:0~5000ppm;
    NET_SNESE_SOUND = 39,                       # 噪音检测,典型值:30~130dB;Noise detection,typical value:30~130dB;
    NET_SENSE_PM25 = 40,                        # PM2.5检测,典型值:0~1000ug/m3;PM2.5 detection,typical value:0~1000ug/m3;
    NET_SENSE_SF6 = 41,                         # SF6浓度检测,典型值:0~3000ppm;Determination of SF6,typical value:0~3000ppm;
    NET_SENSE_O3 = 42,                          # 臭氧浓度检测,典型值:0~100ppm;O3 detection,typical value:0~100ppm;
    NET_SENSE_AMBIENTLIGHT = 43,                # 环境光照检测,典型值:0~20000Lux;ambient light detection,typical value:0~20000Lux;
    NET_SENSE_SIGNINBUTTON = 44,                # 签入按钮;sign in button;
    NET_SENSE_LIQUIDLEVEL = 45,                 # 液位;LiquidLevel;
    NET_SENSE_DISTANCE = 46,                    # 测距;distance;
    NET_SENSE_WATERFLOW = 47,                   # 水流量;water flow;
    NET_SENSE_KEYPRESSS = 48,                   # 按键传感器;Keypress Sensor;
    NET_SENSE_TEMP_AND_HUMI_SM7820B = 49,       # SM7820B温湿度传感器;Sm7820b temperature and humidity sensor;
    NET_SENSE_WATT_HUR_DDSU666 = 50,            # DSU666单相电子式电能表D;Dsu666 single phase electronic watt hour meter D;
    NET_SENSE_CURTAIN_SENSOR = 51,              # 幕帘传感器;Curtain sensor;
    NET_SENSE_CASEPREVENTREMOVE = 52,           # 机壳防拆;chasic anti-tamper;
    NET_SENSE_NUM = 53,                         # 枚举类型总数;enum total;

class EM_NET_DEFENCE_AREA_TYPE(IntEnum):
    """
    防区类型
    protection area type
    """
    EM_NET_DEFENCE_AREA_TYPE_UNKNOW = 0,        # 未知;unknown;
    EM_NET_DEFENCE_AREA_TYPE_INTIME = 1,        # 即时防区;realtime protection area;
    EM_NET_DEFENCE_AREA_TYPE_DELAY = 2,         # 延时防区;delay protection area;
    EM_NET_DEFENCE_AREA_TYPE_FULLDAY = 3,       # 24小时防区;24h protection area;
    EM_NET_DEFENCE_AREA_TYPE_Follow = 4,        # 跟随防区;follow Protection area;
    EM_NET_DEFENCE_AREA_TYPE_MEDICAL = 5,       # 医疗紧急防区;medical protection area;
    EM_NET_DEFENCE_AREA_TYPE_PANIC = 6,         # 恐慌防区;panic Protection area;
    EM_NET_DEFENCE_AREA_TYPE_FIRE = 7,          # 火警防区;fire Protection area;
    EM_NET_DEFENCE_AREA_TYPE_FULLDAYSOUND = 8,  # 24小时有声防区;24h sound Protection area;
    EM_NET_DEFENCE_AREA_TYPE_FULLDATSLIENT = 9, # 24小时无声防区;24h slient Protection area;
    EM_NET_DEFENCE_AREA_TYPE_ENTRANCE1 = 10,    # 出入防区1;entrance Protection area 1;
    EM_NET_DEFENCE_AREA_TYPE_ENTRANCE2 = 11,    # 出入防区2;entrance Protection area 2;
    EM_NET_DEFENCE_AREA_TYPE_INSIDE = 12,       # 内部防区;inside Protection area;
    EM_NET_DEFENCE_AREA_TYPE_OUTSIDE = 13,      # 外部防区;outside Protection area;
    EM_NET_DEFENCE_AREA_TYPE_PEOPLEDETECT = 14, # 人员检测防区;people detect Protection area;
    EM_NET_DEFENCE_AREA_TYPE_ROBBERY = 15,      # 匪警防区;Robbery area;

class EM_DEFENCE_AREA_TYPE(IntEnum):
    """
    防区类型
    defence area type
    """
    EM_DEFENCE_AREA_TYPE_UNKNOWN = 0,           # 未知;Unknown area;
    EM_DEFENCE_AREA_TYPE_INTIME = 1,            # 立即防区;Intime area;
    EM_DEFENCE_AREA_TYPE_DELAY = 2,             # 延时防区;Delay area;
    EM_DEFENCE_AREA_TYPE_DELAY2 = 3,            # 延时防区2;Delay2 area;
    EM_DEFENCE_AREA_TYPE_FOLLOW = 4,            # 跟随防区;Follow area;
    EM_DEFENCE_AREA_TYPE_EXITEND = 5,           # 退出防区;Exitend area;
    EM_DEFENCE_AREA_TYPE_FULLDAY = 6,           # 24小时防区;Fullday area;
    EM_DEFENCE_AREA_TYPE_FIRE = 7,              # 火警防区;Fir area;
    EM_DEFENCE_AREA_TYPE_PANIC = 8,             # 恐慌防区;Panic area;
    EM_DEFENCE_AREA_TYPE_ROBBERY = 9,           # 匪警防区;Robbery area;
    EM_DEFENCE_AREA_TYPE_MEDICAL = 10,          # 医疗紧急防区;Medical area;
    EM_DEFENCE_AREA_TYPE_KEY = 11,              # key防区;key area;

class EM_AREAALARM_TRIGGER_TYPE(IntEnum):
    """
    区域报警触发类型
    area alarm trigger type
    """
    EM_AREAALARM_TRIGGER_TYPE_UNKNOWN = 0,      # 未知;Unknown;
    EM_AREAALARM_TRIGGER_TYPE_ALARM = 1,        # 通道打开;Open;
    EM_AREAALARM_TRIGGER_TYPE_TAMPER = 2,       # 通道防拆;Tamper;
    EM_AREAALARM_TRIGGER_TYPE_MASK = 3,         # 通道遮挡;Mask;
    EM_AREAALARM_TRIGGER_TYPE_SHORT = 4,        # 通道防短;Short;

class EM_IPVERSION(IntEnum):
    """
    IP类型
    IP type
    """
    EM_IPVERSION_IPV4 = 0,                      # IPv4;IPv4;
    EM_IPVERSION_IPV6 = 1,                      # IPv6;IPv6;

class EM_A_NET_WIRELESSDEV_LOWPOWER_TYPE(IntEnum):
    """
    无线设备类型
    wirelesstype
    """
    NET_WIRELESSDEV_UNKNOWN = 0,                # 未知设备;unknowndevice;
    NET_WIRELESSDEV_CONTROL = 1,                # 无线遥控器;wirelesscontrol;
    NET_WIRELESSDEV_DEFENCE = 2,                # 无线防区;wirelessdefence;
    NET_WIRELESSDEV_KEYBOARD = 3,               # 无线键盘;wirelessKeyBoard;
    NET_WIRELESSDEV_MAGNETOMER = 4,             # 无线门磁 此字段协议上已废弃;Wireless door sensor This field is obsolete on the protocol;
    NET_WIRELESSDEV_ALARMBELL = 5,              # 无线警号;wirelessAlarmBell;
    NET_WIRELESSDEV_SMARTLOCK = 6,              # 智能锁;smartlock;

class EM_A_NET_BUS_TYPE(IntEnum):
    """
    总线类型
    BUS type
    """
    NET_BUS_TYPE_UNKNOWN = 0,
    NET_BUS_TYPE_MBUS = 1,                      # M-BUS总线;M-BUS;
    NET_BUS_TYPE_RS485 = 2,                     # RS-485总线;RS-485;
    NET_BUS_TYPE_CAN = 3,                       # CAN总线;CAN;
    NET_BUS_TYPE_NET = 4,                       # 网络设备;internet device;

class EM_SENSOR_ABNORMAL_STATUS(IntEnum):
    """
    探测器状态
    sensor status
    """
    NET_SENSOR_ABNORMAL_STATUS_UNKNOWN = 0,
    NET_SENSOR_ABNORMAL_STATUS_SHORT = 1,       # 短路;short;
    NET_SENSOR_ABNORMAL_STATUS_BREAK = 2,       # 断路;break;
    NET_SENSOR_ABNORMAL_STATUS_INTRIDED = 3,    # 被拆开;intrided;
    NET_SENSOR_ABNORMAL_STATUS_MASK = 4,        # 防遮挡;Mask;
    NET_SENSOR_ABNORMAL_STATUS_NORMAL = 5,      # 正常;Normal;
    NET_SENSOR_ABNORMAL_STATUS_OFFLINE = 6,     # 离线;Offline;
    NET_SENSOR_ABNORMAL_STATUS_ALARM = 7,       # 报警;Alarm;
    NET_SENSOR_ABNORMAL_STATUS_FAULT = 8,       # 故障;Fault;

class EM_A_NET_ALARM_MODE(IntEnum):
    """
    布撤防模式
    Protect/Cancel Protect Mode
    """
    NET_ALARM_MODE_UNKNOWN = -1,                # 未知;Unknown;
    NET_ALARM_MODE_DISARMING = 0,               # 撤防;Cancel Protect;
    NET_ALARM_MODE_ARMING = 1,                  # 布防;Install protect;
    NET_ALARM_MODE_FORCEON = 2,                 # 强制布防;Forceon protect;
    NET_ALARM_MODE_PARTARMING = 3,              # 部分布防;Parting protect;

class EM_A_NET_SCENE_MODE(IntEnum):
    """
    布撤防场景模式
    Arm/Disarm scene mode
    """
    NET_SCENE_MODE_UNKNOWN = 0,                 # 未知场景;Unknown scene;
    NET_SCENE_MODE_OUTDOOR = 1,                 # 外出模式;Outdoor mode;
    NET_SCENE_MODE_INDOOR = 2,                  # 室内模式;Inner mode;
    NET_SCENE_MODE_WHOLE = 3,                   # 全局模式;global mode;
    NET_SCENE_MODE_RIGHTNOW = 4,                # 立即模式;immediate mode;
    NET_SCENE_MODE_SLEEPING = 5,                # 就寝模式;sleeping mode;
    NET_SCENE_MODE_CUSTOM = 6,                  # 自定义模式;mode;

class EM_A_NET_EM_TRIGGER_MODE(IntEnum):
    """
    触发方式
    trigger mode
    """
    NET_EM_TRIGGER_MODE_UNKNOWN = 0,
    NET_EM_TRIGGER_MODE_NET = 1,                # 网络用户(平台或Web);Network user(Platform or Web);
    NET_EM_TRIGGER_MODE_KEYBOARD = 2,           # 键盘;keyboard;
    NET_EM_TRIGGER_MODE_REMOTECONTROL = 3,      # 遥控器;remote control;

class EM_AREAARM_TRIGGERMODE(IntEnum):
    """
    区域防区操作方式
    Trigger mode
    """
    EM_AREAARM_TRIGGERMODE_UNKNOWN = 0,         # 未知;Unknown;
    EM_AREAARM_TRIGGERMODE_KEYPAD = 1,          # 键盘;Keypad;
    EM_AREAARM_TRIGGERMODE_REMOTECONTROL = 2,   # 遥控器;Remote control;
    EM_AREAARM_TRIGGERMODE_USER = 3,            # 用户操作;User;
    EM_AREAARM_TRIGGERMODE_LOCAL = 4,           # 本地;Local;
    EM_AREAARM_TRIGGERMODE_TIMER = 5,           # 定时器;timer;
    EM_AREAARM_TRIGGERMODE_KEY = 6,             # Key类型防区;Key type defense area;
    EM_AREAARM_TRIGGERMODE_REMOTE = 7,          # 远程操作(电话反控、短信反控、手机App、平台客户端等);Remote operation (telephone anti control, SMS anti control, mobile app, platform client, etc.);
    EM_AREAARM_TRIGGERMODE_DSS = 8,             # DSS平台客户端;DSS Platform client;
    EM_AREAARM_TRIGGERMODE_DSSPRO = 9,          # DSSPro平台客户端;DSSPro Platform client;
    EM_AREAARM_TRIGGERMODE_DMSS = 10,           # 手机客户端;Mobile client;

class EM_AREAARM_USER(IntEnum):
    """
    区域防区操作用户
    User
    """
    EM_AREAARM_USER_UNKNOWN = 0,                # 未知;Unknown;
    EM_AREAARM_USER_SUPERVISOR = 1,             # 用户
    EM_AREAARM_USER_MANAGER = 2,                # 管理用户;Manager;
    EM_AREAARM_USER_MASTER = 3,                 # 主用户;Main;
    EM_AREAARM_USER_USER = 4,                   # 普通用户;User;
    EM_AREAARM_USER_TEMPORARY = 5,              # 临时用户;Temporary;
    EM_AREAARM_USER_DURESS = 6,                 # 胁迫用户;Duress;
    EM_AREAARM_USER_PATROL = 7,                 # 巡逻用户;Patrol;

class EM_ARM_STATE(IntEnum):
    """
    布撤防状态
    Arm states
    """
    EM_ARM_STATE_UNKNOWN = 0,                   # 未知;Unknown;
    EM_ARM_STATE_TOTAL_ARMING = 1,              # Total布防;Total;
    EM_ARM_STATE_PARTIAL1_ARMING = 2,           # partial1布防;partial1;
    EM_ARM_STATE_PARTIAL2_ARMING = 3,           # partial2布防;partial2;
    EM_ARM_STATE_PARTIAL1_PARTIAL2_ARMING = 4,  # partial1+2布防;partial1+2;
    EM_ARM_STATE_FORCEARMING = 5,               # 强制布防;force arming;
    EM_ARM_STATE_DISARMING = 6,                 # 撤防;disarming;

class EM_RCEMERGENCY_CALL_TYPE(IntEnum):
    """
    紧急救助事件类型
    Emergency Help Event Type
    """
    EM_RCEMERGENCY_CALL_UNKNOWN = 0,
    EM_RCEMERGENCY_CALL_FIRE = 1,               # 火警;Fire;
    EM_RCEMERGENCY_CALL_DURESS = 2,             # 胁迫;Forced;
    EM_RCEMERGENCY_CALL_ROBBER = 3,             # 匪警;Robber;
    EM_RCEMERGENCY_CALL_MEDICAL = 4,            # 医疗;Medical;
    EM_RCEMERGENCY_CALL_EMERGENCY = 5,          # 紧急;Emergency;
    EM_RCEMERGENCY_CALL_PANIC = 6,              # 恐慌;Panic;

class EM_RCEMERGENCY_MODE_TYPE(IntEnum):
    """
    报警方式
    alarm method
    """
    EM_RCEMERGENCY_MODE_UNKNOWN = 0,
    EM_RCEMERGENCY_MODE_KEYBOARD = 1,           # 键盘;keyboard;
    EM_RCEMERGENCY_MODE_WIRELESS_CONTROL = 2,   # 遥控器;remote control;

class EM_POWER_TYPE(IntEnum):
    """
    电源类型
    Power Type
    """
    EM_POWER_TYPE_MAIN = 0,                     # 主电源;Main Power;
    EM_POWER_TYPE_BACKUP = 1,                   # 备用电源;Spare Power;

class EM_POWERFAULT_EVENT_TYPE(IntEnum):
    """
    电源故障事件类型
    the Type of Power Fault Event
    """
    EM_POWERFAULT_EVENT_UNKNOWN = -1,           # 未知;Unknown;
    EM_POWERFAULT_EVENT_LOST = 0,               # 掉电、电池不在位;Power down, has no battery;
    EM_POWERFAULT_EVENT_LOST_ADAPTER = 1,       # 适配器不在位;Has no adapter;
    EM_POWERFAULT_EVENT_LOW_BATTERY = 2,        # 电池欠压;Battery under voltage;
    EM_POWERFAULT_EVENT_LOW_ADAPTER = 3,        # 适配器欠压;Adapter under voltage;
    EM_POWERFAULT_EVENT_LOW_ADAPTER_LOST_BATTERY = 4,    # 适配器欠压,电池掉电;Low Adapter Lost Battery;
    EM_POWERFAULT_EVENT_LESS_ADAPTER_LOW_BATTERY = 5,    # 适配器低压供电,电池欠压;Less Adapter Low Battery;
    EM_POWERFAULT_EVENT_LESS_ADAPTER_LOST_BATTERY = 6,    # 适配器低压供电,电池掉电;Less Adapter Lost Battery;
    EM_POWERFAULT_EVENT_LOST_ADAPTER_LOST_BATTERY = 7,    # 适配器与电池都掉电;Lost Adapter Lost Battery;
    EM_POWERFAULT_EVENT_LOW_ADAPTER_LOW_BATTERY = 8,    # 适配器与电池都欠压;Low Adapter Low Battery;

class EM_ALARM_CHASSISINTRUDED_DEV_TYPE(IntEnum):
    """
    设备类型
    Equipment type
    """
    EM_ALARM_CHASSISINTRUDED_DEV_UNKNOWN = 0,   # 未知;unknown;
    EM_ALARM_CHASSISINTRUDED_DEV_CONTROLLER = 1,    # 控制器（如：报警主机）;controller (eg: control panel);
    EM_ALARM_CHASSISINTRUDED_DEV_RS485EXPANSIONMODULE = 2,    # RS485扩展报警输入/输出模块;RS485 extended alarm input/output module;
    EM_ALARM_CHASSISINTRUDED_DEV_MBUSEXPANSIONMODULE = 3,    # MBUS扩展报警输入/输出模块;MBUS extended alarm input/output module;
    EM_ALARM_CHASSISINTRUDED_DEV_KEYBOARD = 4,  # 键盘;keyboard;
    EM_ALARM_CHASSISINTRUDED_DEV_SIREN = 5,     # 警号;siren;

class EM_A_GSMFIELD_FAULT_TYPE(IntEnum):
    """
    无线网络通讯错误类型
    Fault type
    """
    GSMFIELD_FAULT_UNKNOWN = 0,                 # 未知;Unknown;
    GSMFIELD_FAULT_GSMModule = 1,               # 通信模块掉线;Comunicating module offline;
    GSMFIELD_FAULT_SIMCard = 2,                 # 未插SIM卡;No sim card;

class EM_A_NET_EM_SET_ALARMREGION_INFO(IntEnum):
    """
    设置的操作类型
    Type of set operate
    """
    NET_EM_SET_ALARMREGION_INFO_UNKNOWN = 0,    # 未知;Unknown;
    NET_EM_SET_ALARMREGION_INFO_ARMMODE = 1,    # 设置布防模式， 此时CLIENT_SetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_SET_ALARMMODE， pstuOutParam类型为 NET_OUT_SET_ALARMMODE;Set arm mode CLIENT_SetAlarmRegionInfo:(pstuInParam: NET_IN_SET_ALARMMODE pstuOutParam: NET_OUT_SET_ALARMMODE);
    NET_EM_SET_ALARMREGION_INFO_BYPASSMODE = 2, # 设置旁路模式， 此时CLIENT_SetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_SET_BYPASSMODE， pstuOutParam类型为 NET_OUT_SET_BYPASSMODE;Set bypass mode CLIENT_SetAlarmRegionInfo:(pstuInParam: NET_IN_SET_BYPASSMODE pstuOutParam: NET_OUT_SET_BYPASSMODE);
    NET_EM_SET_ALARMREGION_INFO_OUTPUTSTATE = 3,    # 设置输出状态， 此时CLIENT_SetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_SET_OUTPUT_STATE， pstuOutParam类型为 NET_OUT_SET_OUTPUT_STATE;Set output state CLIENT_SetAlarmRegionInfo:(pstuInParam: NET_IN_SET_OUTPUT_STATE pstuOutParam: NET_OUT_SET_OUTPUT_STATE);

class EM_ARM_TYPE(IntEnum):
    """
    布撤防类型
    arm type
    """
    EM_ARM_TYPE_UNKNOWN = 0,                    # 未知;unknown;
    EM_ARM_TYPE_TOTAL_ARMING = 1,               # Total布防;Total arming;
    EM_ARM_TYPE_PARTIAL1_ARMING = 2,            # partial1布防;partial1 arming;
    EM_ARM_TYPE_PARTIAL2_ARMING = 3,            # partial2布防;partial2 arming;
    EM_ARM_TYPE_PARTIAL_ARMING = 4,             # partial1+2布防;partial1+2 arming;
    EM_ARM_TYPE_DENFENCE_ARMING = 5,            # 强制布防;Force arming;
    EM_ARM_TYPE_DISARMING = 6,                  # 撤防;disarming;

class EM_A_NET_EM_SCENE_MODE(IntEnum):
    """
    布防的情景模式
    Deployment scenario mode
    """
    NET_EM_SCENE_MODE_UNKNOWN = 0,              # 未知模式;Unknown mode;
    NET_EM_SCENE_MODE_OUTDOOR = 1,              # 外出模式;OutDoor mode;
    NET_EM_SCENE_MODE_INDOOR = 2,               # 在家模式;AtHome mode;
    NET_EM_SCENE_MODE_WHOLE = 3,                # 全局模式;Whole mode;
    NET_EM_SCENE_MODE_RIGHTNOW = 4,             # 立即模式;RightNow mode;
    NET_EM_SCENE_MODE_AUTO = 5,                 # 自动模式;Auto Mode;
    NET_EM_SCENE_MODE_FORCE = 6,                # 强制模式;Force Mode;
    NET_EM_SCENE_MODE_CUSTOM = 7,               # 自定义模式; Mode;
    NET_EM_SCENE_MODE_SLEEPING = 8,             # 就寝模式;Sleeping Mode;

class EM_BYPASSMODE_TYPE(IntEnum):
    """
    旁路模式类型
    Bypass mode type
    """
    EM_BYPASSMODE_TYPE_UNKNOWN = 0,             # 未知;Unknown;
    EM_BYPASSMODE_TYPE_OFF = 1,                 # 不使用;Not use;
    EM_BYPASSMODE_TYPE_ACTIVE = 2,              # 正常;Normal;
    EM_BYPASSMODE_TYPE_BYPASSED = 3,            # 旁路;Bypass;
    EM_BYPASSMODE_TYPE_ISOLATED = 4,            # 隔离;Isolate;
    EM_BYPASSMODE_TYPE_TEST = 5,                # 测试;Test;

class EM_OUTPUT_TYPE(IntEnum):
    """
    输出通道类型
    output channel type
    """
    EM_OUTPUT_TYPE_UNKNOWN = 0,                 # 未知;unknown;
    EM_OUTPUT_TYPE_SIREN = 1,                   # 警号;siren;
    EM_OUTPUT_TYPE_ALARMOUT = 2,                # 输出通道;out;

class EM_A_NET_EM_GET_ALARMREGION_INFO(IntEnum):
    """
    获取的操作类型
    Type of get operate
    """
    NET_EM_GET_ALARMREGION_INFO_UNKNOWN = 0,    # 未知;Unknown;
    NET_EM_GET_ALARMREGION_INFO_ALARMCAPS = 1,  # 获取防区能力， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_ALARMCAPS， pstuOutParam类型为 NET_OUT_GET_ALARMCAPS;Get alarm capability. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_ALARMCAPS pstuOutParam: NET_OUT_GET_ALARMCAPS);
    NET_EM_GET_ALARMREGION_INFO_ARMMODE = 2,    # 获取布防状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_ALARMMODE， pstuOutParam类型为 NET_OUT_GET_ALARMMODE;Get arm mode. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_ALARMMODE pstuOutParam: NET_OUT_GET_ALARMMODE);
    NET_EM_GET_ALARMREGION_INFO_BYPASSMODE = 3, # 获取旁路状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_BYPASSMODE， pstuOutParam类型为 NET_OUT_GET_BYPASSMODE;Get bypass mode. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_BYPASSMODE pstuOutParam: NET_OUT_GET_BYPASSMODE);
    NET_EM_GET_ALARMREGION_INFO_AREAZONES = 4,  # 获取区域防区， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_AREAZONES， pstuOutParam类型为 NET_OUT_GET_AREAZONES;Get area zones. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_AREAZONES pstuOutParam: NET_OUT_GET_AREAZONES);
    NET_EM_GET_ALARMREGION_INFO_ALLINSLOTS = 5, # 获取所有的报警防区， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_ALLINSLOTS， pstuOutParam类型为 NET_OUT_GET_ALLINSLOTS;Get all in slots. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_ALLINSLOTS pstuOutParam: NET_OUT_GET_ALLINSLOTS);
    NET_EM_GET_ALARMREGION_INFO_ALLOUTSLOTS = 6,    # 获取所有的报警输出， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_ALLOUTSLOTS， pstuOutParam类型为 NET_OUT_GET_ALLOUTSLOTS;Get all out slots. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_ALLOUTSLOTS pstuOutParam: NET_OUT_GET_ALLOUTSLOTS);
    NET_EM_GET_ALARMREGION_INFO_ZONECONNECTIONSSTATUS = 7,    # 获取防区连接状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_CONNECTIONSTATUS， pstuOutParam类型为 NET_OUT_GET_CONNECTIONSTATUS;Get zone connection status. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_CONNECTIONSTATUS pstuOutParam: NET_OUT_GET_CONNECTIONSTATUS);
    NET_EM_GET_ALARMREGION_INFO_AREASTATUS = 8, # 获取区域状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_AREAS_STATUS， pstuOutParam类型为 NET_OUT_GET_AREAS_STATUS;Get area status. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_AREAS_STATUS pstuOutParam: NET_OUT_GET_AREAS_STATUS);
    NET_EM_GET_ALARMREGION_INFO_OUTPUTSTATE = 9,    # 获取输出状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_OUTPUT_STATE， pstuOutParam类型为 NET_OUT_GET_OUTPUT_STATE;Get output state. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_OUTPUT_STATE pstuOutParam: NET_OUT_GET_OUTPUT_STATE);
    NET_EM_GET_ALARMREGION_INFO_ZONESTROUBLE = 10,    # 获取防区故障信息， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_ZONES_TROUBLE， pstuOutParam类型为 NET_OUT_GET_ZONES_TROUBLE;Get zones trouble. CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_ZONES_TROUBLE pstuOutParam: NET_OUT_GET_ZONES_TROUBLE);
    NET_EM_GET_ALARMREGION_INFO_CHANNELSSTATE = 11,    # 获取通道状态， 此时CLIENT_GetAlarmRegionInfo接口中的pstuInParam类型为 NET_IN_GET_CHANNELS_STATE， pstuOutParam类型为 NET_OUT_GET_CHANNELS_STATE;Get channels state, CLIENT_GetAlarmRegionInfo:(pstuInParam: NET_IN_GET_CHANNELS_STATE pstuOutParam: NET_OUT_GET_CHANNELS_STATE);

class EM_GET_AREASSTATUS_TYPE(IntEnum):
    """
    获取异常防区类型
    get area status
    """
    EM_GET_AREASSTATUS_TYPE_UNKNOWN = 0,        # 未知;unknown;
    EM_GET_AREASSTATUS_TYPE_ACTIVE = 1,         # 激活;active;
    EM_GET_AREASSTATUS_TYPE_OPEN = 2,           # 打开;open;

class EM_ZONE_STATUS(IntEnum):
    """
    防区异常状态
    zone status
    """
    EM_ZONE_STATUS_UNKNOWN = 0,                 # 未知;unknown;
    EM_ZONE_STATUS_ALARM = 1,                   # 防区报警/打开;open;
    EM_ZONE_STATUS_TAMPER = 2,                  # 防区防拆;tamper;
    EM_ZONE_STATUS_MASK = 3,                    # 防区防遮挡;mask;
    EM_ZONE_STATUS_SHORT = 4,                   # 防区短路;short;
    EM_ZONE_STATUS_NORMAL = 5,                  # 防区正常;normal;

class EM_ZONE_TROUBLE_TYPE(IntEnum):
    """
    防区故障类型
    zone trouble type
    """
    EM_ZONE_TROUBLE_TYPE_UNKNOWN = 0,           # 未知;unknown;
    EM_ZONE_TROUBLE_TYPE_TAMPER = 1,            # 通道防拆;tamper;
    EM_ZONE_TROUBLE_TYPE_MASK = 2,              # 通道遮挡;Mask;
    EM_ZONE_TROUBLE_TYPE_SHORT = 3,             # 通道防短;short;
    EM_ZONE_TROUBLE_TYPE_ALARM = 4,             # 通道报警/打开;Open;
    EM_ZONE_TROUBLE_TYPE_NORMAL = 5,            # 通道正常;Normal;

class EM_CHANNELS_STATE_TYPE(IntEnum):
    """
    通道类型
    channels type
    """
    EM_CHANNELS_STATE_TYPE_UNKNOWN = 0,         # 未知;unknown;
    EM_CHANNELS_STATE_TYPE_ALL = 1,             # 所有通道;all channels;
    EM_CHANNELS_STATE_TYPE_ALARMIN = 2,         # 报警输入通道;alarm in;
    EM_CHANNELS_STATE_TYPE_ALARMOUT = 3,        # 报警输出通道;alarm out;
    EM_CHANNELS_STATE_TYPE_SIREN = 4,           # 警号通道;siren;

class EM_DEV_STATUS(IntEnum):
    """
    设备状态
    Device status
    """
    EM_DEV_STATUS_UNKNOWN = -1,                 # 未知;Unknown;
    EM_DEV_STATUS_OFFLINE = 0,                  # 离线;Off line;
    EM_DEV_STATUS_ONLINE = 1,                   # 在线;On line;

class EM_OUTPUT_STATE(IntEnum):
    """
    输出状态
    Output state
    """
    EM_OUTPUT_STATE_UNKNOWN = -1,               # 未知;Unknown;
    EM_OUTPUT_STATE_CLOSE = 0,                  # 关闭;Close;
    EM_OUTPUT_STATE_OPEN = 1,                   # 打开;Open;

class EM_FIRE_TYPE(IntEnum):
    """
    报警框所属位置
    The location of the alarm frame
    """
    EM_FIRE_TYPE_UNKNOWN = -1,                  # 位置未知;Location unknown;
    EM_FIRE_TYPE_DETECT_AREA = 0,               # 报警框所属检测区;The detection area to which the alarm frame belongs;
    EM_FIRE_TYPE_NO_DETECT_AREA = 1,            # 报警框所属非检测区;Non-detection area to which the alarm frame belongs;
    EM_FIRE_TYPE_DETECT_AREA_ALL = 2,           # 检测区和检测区同时存在;The detection zone and the detection zone exist at the same time;

class EM_RADAR_POINTTYPE(IntEnum):
    """
    点类型的掩码
    point type
    """
    EM_RADAR_POINTTYPE_UNKNOWN = 0,             # 未知;unknown;
    EM_RADAR_POINTTYPE_ALARMPOINT = 1,          # 当前点是报警区的报警点;alarm point of alarm area;
    EM_RADAR_POINTTYPE_LINKMONITORPOINT = 2,    # 当前点是正在被联动监控的点;points being monitored by linkage;
    EM_RADAR_POINTTYPE_DISAPPEARTRACKPOINT = 3, # 当前点是消失的轨迹点;disappear track point;

class EM_RADAR_OBJECTTYPE(IntEnum):
    """
    点所指对象的类型的掩码
    radar object type
    """
    EM_RADAR_OBJECTTYPE_UNKNOWN = 0,            # 未识别目标;unknown;
    EM_RADAR_OBJECTTYPE_PERSON = 1,             # 目标为人;person;
    EM_RADAR_OBJECTTYPE_VEHICLE = 2,            # 目标为交通工具;vehicle;
    EM_RADAR_OBJECTTYPE_TREE = 3,               # 目标为树;tree;
    EM_RADAR_OBJECTTYPE_BUILIDING = 4,          # 目标为建筑物;building;
    EM_RADAR_OBJECTTYPE_SCREEN = 5,             # 目标为屏幕;screen;
    EM_RADAR_OBJECTTYPE_ANIMAL = 6,             # 目标为动物;animal;
    EM_RADAR_OBJECTTYPE_BIG_SHIP = 7,           # 目标为大船;big ship;
    EM_RADAR_OBJECTTYPE_MID_SHIP = 8,           # 目标为中船;middle ship;
    EM_RADAR_OBJECTTYPE_SMALL_SHIP = 9,         # 目标为小船;small ship;
    EM_RADAR_OBJECTTYPE_STATIONARY_TARGET_TYPE = 10,    # 目标为静止目标类型;stationary target type;

class EM_RADAR_DETECT_OBJECT_TYPE(IntEnum):
    """
    雷达检测对象类型
    Radar detect object type
    """
    EM_RADAR_DETECT_OBJECT_UNKNOWN = 0,         # 未知;Unknown;
    EM_RADAR_DETECT_OBJECT_HUMAN = 1,           # 人;Human;
    EM_RADAR_DETECT_OBJECT_VEHICLE = 2,         # 车;Vehicle;

class EM_RADAR_ALARM_TYPE(IntEnum):
    """
    雷达报警类型
    Radar alarm type
    """
    EM_RADAR_ALARM_TYPE_UNKNOWN = 0,            # 未知;Unknown;
    EM_RADAR_ALARM_TYPE_ALARM = 1,              # 报警;Alarm;
    EM_RADAR_ALARM_TYPE_WARNING = 2,            # 预警;Warning;

class EM_DETECT_SENSOR_TYPE(IntEnum):
    """
    探测物体的传感器类型
    Sensor type for detecting objects
    """
    EM_DETECT_SENSOR_TYPE_UNKNOWN = 0,          # 未知;Unknown;
    EM_DETECT_SENSOR_TYPE_COIL = 1,             # 线圈;Coil;
    EM_DETECT_SENSOR_TYPE_VIDEO = 2,            # 视频;Video;
    EM_DETECT_SENSOR_TYPE_RADAR = 3,            # 雷达;Radar;
    EM_DETECT_SENSOR_TYPE_5G = 4,               # 5G;5G;
    EM_DETECT_SENSOR_TYPE_FUSION = 5,           # 融合;Fusion;

class EM_VEHICLEINOUT_CAR_TYPE(IntEnum):
    """
    车辆类型
    Vehicle type
    """
    EM_VEHICLEINOUT_CAR_TYPE_UNKNOWN = 0,       # 未知类型;Unknown;
    EM_VEHICLEINOUT_CAR_TYPE_CAR = 1,           # 小型客车;Car;
    EM_VEHICLEINOUT_CAR_TYPE_VAN = 2,           # 面包车;Van;
    EM_VEHICLEINOUT_CAR_TYPE_TRUCK = 3,         # 货车;Truck;
    EM_VEHICLEINOUT_CAR_TYPE_BUS = 4,           # 公交车;Bus;
    EM_VEHICLEINOUT_CAR_TYPE_LORRY = 5,         # 大货车;Lorry;
    EM_VEHICLEINOUT_CAR_TYPE_CART = 6,          # 大车;Cart;
    EM_VEHICLEINOUT_CAR_TYPE_NONMOTOR = 7,      # 非机动车;NoNotor;
    EM_VEHICLEINOUT_CAR_TYPE_HUMAN = 8,         # 人;Human;
    EM_VEHICLEINOUT_CAR_TYPE_SPECAIL = 9,       # 特殊值;Specail value;

class EM_TRAFFIC_FLOW_STATUS(IntEnum):
    """
    流量状态
    Flow status
    """
    EM_TRAFFIC_FLOW_STATUS_UNKNOWN = 0,         # 未知;Unknown;
    EM_TRAFFIC_FLOW_STATUS_CONGESTION = 1,      # 交通拥堵;Traffic congestion;
    EM_TRAFFIC_FLOW_STATUS_SMOOTH = 2,          # 交通畅通;Smooth traffic;

class EM_VIRTUAL_COIL_OCCUPANCY_STATUS(IntEnum):
    """
    虚拟线圈占用状态
    Virtual coil occupancy status
    """
    EM_VIRTUAL_COIL_OCCUPANCY_STATUS_UNKNOWN = -1,    # 未知;Unknown;
    EM_VIRTUAL_COIL_OCCUPANCY_STATUS_UNOCCUPY = 0,    # 未占用;Unoccupy;
    EM_VIRTUAL_COIL_OCCUPANCY_STATUS_OCCUPY = 1,    # 占用;Occupy;

class EM_NET_CARTYPE(IntEnum):
    """
    车辆类型
    Car Type
    """
    NET_CARTYPE_UNKNOW = 0,                     # 未知;Unknow;
    NET_CARTYPE_PASSENGERCAR = 1,               # 客车;Passengercar;
    NET_CARTYPE_LARGETRUCK = 2,                 # 大货车;Largetruck;
    NET_CARTYPE_MIDTRUCK = 3,                   # 中货车;Midtruck;
    NET_CARTYPE_SALOONCAR = 4,                  # 轿车;Salooncar;
    NET_CARTYPE_MICROBUS = 5,                   # 面包车;Microbus;
    NET_CARTYPE_MICROTRUCK = 6,                 # 小货车;Microtruck;
    NET_CARTYPE_TRICYCLE = 7,                   # 三轮车;Tricycle;
    NET_CARTYPE_MOTOR = 8,                      # 摩托车;Motor;
    NET_CARTYPE_PASSERBY = 9,                   # 行人;Passerby;
    NET_CARTYPE_SUVMPV = 10,                    # SUV-MPV;SUV-MPV;
    NET_CARTYPE_MIDPASSENGERCAR = 11,           # 中客车;Midpassengercar;
    NET_CARTYPE_TANKCAR = 12,                   # 危化品车辆(特殊车辆);Tank car;
    NET_CARTYPE_SUV = 13,                       # SUV;SUV;
    NET_CARTYPE_MPV = 14,                       # MPV;MPV;
    NET_CARTYPE_BUS = 15,                       # 公交车;Bus;
    NET_CARTYPE_PICKUP = 16,                    # 皮卡车;Pickup;
    NET_CARTYPE_MINICARRIAGE = 17,              # 微型车;Minicarriage;
    NET_CARTYPE_OILTANKTRUCK = 18,              # 油罐车(特殊车辆);Oiltanktruck;
    NET_CARTYPE_SLOTTANKCAR = 19,               # 槽罐车(特殊车辆);Slottankcar;
    NET_CARTYPE_RESERVED1 = 20,                 # 保留1(特殊车辆);Reserved1;
    NET_CARTYPE_DREGSCAR = 21,                  # 渣土车(特殊车辆);Dregscar;
    NET_CARTYPE_CONCRETEMIXERTRUCK = 22,        # 混凝土搅拌车(特殊车辆);Concretemixertruck;
    NET_CARTYPE_TAXI = 23,                      # 出租车(特殊车辆);Taxt;
    NET_CARTYPE_POLICE = 24,                    # 警车(特殊车辆);Police;
    NET_CARTYPE_AMBULANCE = 25,                 # 救护车(特殊车辆);Ambulance;
    NET_CARTYPE_GENERAL = 26,                   # 普通车(特殊车辆);General;
    NET_CARTYPE_WATERINGCAR = 27,               # 洒水车(特殊车辆);Wateringcar;
    NET_CARTYPE_RESERVED2 = 28,                 # 保留2(特殊车辆);Reserved2;
    NET_CARTYPE_FIREENGINE = 29,                # 消防车(特殊车辆);Fireengine;
    NET_CARTYPE_TRACTOR = 30,                   # 拖拉机(特殊车辆);Tractor;
    NET_CARTYPE_MACHINESHOPTRUCK = 31,          # 工程车(特殊车辆);Machineshopiruck;
    NET_CARTYPE_POWERLOTVEHICLE = 32,           # 粉粒物料车(特殊车辆);Powerlotvehicle;
    NET_CARTYPE_SUCTIONSEWAGETRUCK = 33,        # 吸污车(特殊车辆);Suctionsewagetruck;
    NET_CARTYPE_NORMALVEHICLETANKTRUCK = 34,    # 普通罐车(特殊车辆);NormalVehicleTankTruck;
    NET_CARTYPE_TWOCYCLE = 35,                  # 二轮车;Twocycle;

class EM_CAR_PASSING_MOVE_STATE(IntEnum):
    """
    物体进入还是离开
    whether the object enters or leaves
    """
    EM_CAR_PASSING_MOVE_STATE_UNKNOWN = 0,      # 未知;Unknown;
    EM_CAR_PASSING_MOVE_STATE_ENTER = 1,        # 进入;Enter;
    EM_CAR_PASSING_MOVE_STATE_LEAVE = 2,        # 离开;Leave;

class EM_A_EMUM_VIDEO_ANALYSE_OBJECT_TYPE(IntEnum):
    """
    物体类型
    Video Analyse Object Type
    """
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_UNKNOWN = -1,    # 未知的;Unknown;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_ALL = 0,     # 所有物体;All;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_HUMAN = 1,   # 人;Human;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_VEHICLE = 2, # 机动车，不包括非机动车;Vehicle;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FIRE = 3,    # 火;Fire;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SMOKE = 4,   # 烟;Smoke;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PLATE = 5,   # 车牌;Plate;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_HUMANFACE = 6,    # 人脸;HumanFace;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_CONTAINER = 7,    # 集装箱;Container;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_ANIMAL = 8,  # 动物;Animal;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_TRAFFICLIGHT = 9,    # 交通灯;TrafficLight;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PASTEPAPER = 10,    # 贴条(ATM);PastePaper;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_HUMANHEAD = 11,    # 人头(客流量统计用，包括正面及后脑勺);HumanHead;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_LINE = 12,   # 交通线;Line;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_ENTITY = 13, # 物件;Entity;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BULLETHOLE = 14,    # 弹孔;BulletHole;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FACEPRIVATEDATA = 15,    # 人脸特征算法私有数据;FacePrivateData;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SIMPLEVEHICLE = 16,    # 机动车（仅用于结构化信息）;SimpleVehicle;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_NONMOTOR = 17,    # 非机动车;NonMotor;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SIGNALFLOW = 18,    # 信号机流量;SignalFlow;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PEDESTRAIN = 19,    # 人行道行人信息;Pedestrain;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_DETAILSNAP = 20,    # 联动细节相机信息;DetailSnap;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_XRAYIMAGE = 21,    # 光(车站X光检测)物品检测影像;XRayImage;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SHOPPRESENCE = 22,    # 占道经营物体;ShopPresence;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FLOWBUSINESS = 23,    # 流动摊贩物体;FlowBusiness;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_WATERLEVELRULER = 24,    # 水位尺;WaterLevelRuler;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BOAT = 25,   # 船只;Boat;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FRUIT = 26,  # 水果;Fruit;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BARCODE = 27,    # 二维码;BarCode;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_GLOVE = 28,  # 手套;Glove;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_LADDER = 29, # 梯子;Ladder;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_CURTAIN = 30,    # 布幔;Curtain;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FENCE = 31,  # 围栏;Fence;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SIGNBOARD = 32,    # 标识牌;Signboard;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_ELECTRICBELT = 33,    # 电力安全带;ElectricBelt;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PARKINGSPACE = 34,    # 停车场车位;ParkingSpace;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_RMB = 35,    # 人民币;RMB;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_KEY = 36,    # 钥匙;Key;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_SEAL = 37,   # 印章;Seal;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FOREIGNCURRENCY = 38,    # 外币;ForeignCurrency;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_WATERFLOATING = 39,    # 水面漂浮物;WaterFloating;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FIRELANEJAMS = 40,    # 消防占道物;FireLaneJams;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_OCR = 41,    # OCR识别目标（例如证件上的人脸抠图，名字，号码，姓名，地址等）;OCR;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PRAM = 42,   # 婴儿车;Pram;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_LUGGAGE = 43,    # 大件行李;Luggage;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FOREIGNMATTER = 44,    # 异物;ForeignMatter;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PACKAGE = 45,    # 包裹;Package;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_RADARDETECT = 46,    # 雷达检测物体;RadarDetect;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_PLANE = 47,  # 飞机;Plane;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BAG = 48,    # 箱包;Bag;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BOX = 49,    # 盒子;Box;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_HIGHTOSSCARD = 50,    # 高空抛物目标;HighTossCard;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_CARD = 51,   # 卡片;Card;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_EMPTYRADAR = 52,    # 空雷达物体，暂时只包含速度;EmptyRadar;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_WHEEL = 53,  # 车轮;Wheel;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_WATER = 54,  # 水;Water;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_BULK = 55,   # 大块物;Bulk;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_ROADCONE = 56,    # 路锥;Roadcone;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FIREEXTINGUISHER = 57,    # 灭火器;FireExtinguisher;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_UMBRELLA = 58,    # 伞;Umbrella;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_FISHINGROD = 59,    # 钓鱼竿;FishingRod;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_HANGINGPACKAGE = 60,    # 吊物（硅包、钢包、铁包）;HangingPackage;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_TRIPCODE = 61,    # 行程码;TripCode;
    EMUM_VIDEO_ANALYSE_OBJECT_TYPE_UNIFORM = 62,    # 制服;UniForm;

class EM_A_NET_EVENT_OPERATE_TYPE(IntEnum):
    """
    操作类型枚举
    Operation type enumeration
    """
    NET_EVENT_OPERATE_TYPE_UNKOWN = 0,          # 未知;Unkown;
    NET_EVENT_OPERATE_TYPE_ADD = 1,             # 增加;add;
    NET_EVENT_OPERATE_TYPE_DELETE = 2,          # 删除;delete;
    NET_EVENT_OPERATE_TYPE_MODIFY = 3,          # 修改;modify;

class EM_A_NET_EVENT_USER_TYPE(IntEnum):
    """
    用户类型枚举
    user type enumeration
    """
    NET_EVENT_USER_TYPE_UNKOWN = 0,             # 未知;Unkown;
    NET_EVENT_USER_TYPE_KEYPAD = 1,             # 键盘;keypad;

class EM_A_NET_EVENT_DEVICE_TYPE(IntEnum):
    """
    设备类型枚举
    device type enumeration
    """
    NET_EVENT_DEVICE_TYPE_UNKOWN = 0,           # 未知;Unkown;
    NET_EVENT_DEVICE_TYPE_CARD = 1,             # 卡片;card;

class EM_AUTOREGISTER_TYPE(IntEnum):
    """
    主动注册命令类型 ;The type of auto register command
    """
    DISCONNECT = -1,                            # 验证期间设备断线回调; Device disconnection callback during the verification period
    SERIAL_RETURN = 1,                          # 设备注册携带序列号 对应 char* szDevSerial; Device send out SN callback char* szDevSerial
    AUTOREGISTER_RETURN = 2,                    # 设备注册携带序列号和令牌 对应NET_CB_AUTOREGISTER; when device registering,serial number and token to carry, corresponding NET_CB_AUTOREGISTER
    NOTIFY_IP_RETURN = 3,                       # 设备仅上报IP, 不作为主动注册用, 用户获取ip后只能按照约定的端口按照非主动注册的类型登录; Equipment is only reported IP, not used for active registration

class EM_WATERDATA_STAT_SERVER_SUPPORT(IntEnum):
    """
    当前是否具备水质检测功能
    Does it have water quality detection function at present
    """
    EM_WATERDATA_STAT_SERVER_SUPPORT_UNKNOWN = -1,    # 未知;Unknown;
    EM_WATERDATA_STAT_SERVER_SUPPORT_NO = 0,    # 不支持;Not support;
    EM_WATERDATA_STAT_SERVER_SUPPORT_YES = 1,   # 支持;support;

class EM_SUPPORT_LOCALDATA_STORE(IntEnum):
    """
    是否支持本地存储
    Does it support local storage
    """
    EM_SUPPORT_LOCALDATA_STORE_UNKNOWN = -1,    # 未知;Unknown;
    EM_SUPPORT_LOCALDATA_STORE_NO = 0,          # 不支持;Not support;
    EM_SUPPORT_LOCALDATA_STORE_YES = 1,         # 支持;support;

class EM_WATER_DETECTION_ALARM_TYPE(IntEnum):
    """
    事件报警类型
    Event alarm type
    """
    EM_WATER_DETECTION_ALARM_TYPE_UNKNOWN = 0,  # 未知;Unknown;
    EM_WATER_DETECTION_ALARM_TYPE_QUALITY = 1,  # 水质类别;Water quality category;
    EM_WATER_DETECTION_ALARM_TYPE_PH = 2,       # PH;PH;
    EM_WATER_DETECTION_ALARM_TYPE_NTU = 3,      # 浊度值;Turbidity value;
    EM_WATER_DETECTION_ALARM_TYPE_NH3_N = 4,    # 氨氮值;Ammonia nitrogen value;
    EM_WATER_DETECTION_ALARM_TYPE_TN = 5,       # 总氮值;Total nitrogen value;
    EM_WATER_DETECTION_ALARM_TYPE_SD = 6,       # 透明度值;Transparency value;
    EM_WATER_DETECTION_ALARM_TYPE_COD = 7,      # 化学需氧量;Chemical oxygen demand;
    EM_WATER_DETECTION_ALARM_TYPE_NN = 8,       # 亚硝酸盐氮;Nitrite nitrogen;
    EM_WATER_DETECTION_ALARM_TYPE_DO = 9,       # 溶解氧;dissolved oxygen;
    EM_WATER_DETECTION_ALARM_TYPE_CHL_A = 10,   # 叶绿素a;Chlorophyll a;
    EM_WATER_DETECTION_ALARM_TYPE_TP = 11,      # 总磷;Total phosphorus;
    EM_WATER_DETECTION_ALARM_TYPE_CODMN = 12,   # 高锰酸盐指数范围;Permanganate index range;
    EM_WATER_DETECTION_ALARM_TYPE_SS = 13,      # 悬浮物;Suspended solids;
    EM_WATER_DETECTION_ALARM_TYPE_BOD_5 = 14,   # 五日生化需氧量;Five day biochemical oxygen demand;
    EM_WATER_DETECTION_ALARM_TYPE_NO3_N = 15,   # 硝酸盐;Nitrate;
    EM_WATER_DETECTION_ALARM_TYPE_TSI = 16,     # 富营养状况指数;Eutrophication index;
    EM_WATER_DETECTION_ALARM_TYPE_SMELLY_LEVEL = 17,    # 黑臭等级;Smelly level;

class EM_WATER_QUALITY(IntEnum):
    """
    水质类别，越小越好
    Water quality category, the smaller the better
    """
    EM_WATER_QUALITY_UNKNOWN = 0,               # 未知;Unknown;
    EM_WATER_QUALITY_1 = 1,                     # 1类;Class 1;
    EM_WATER_QUALITY_2 = 2,                     # 2类;Class 2;
    EM_WATER_QUALITY_3 = 3,                     # 3类;Class 3;
    EM_WATER_QUALITY_4 = 4,                     # 4类;Class 4;
    EM_WATER_QUALITY_5 = 5,                     # 5类;Class 5;

class EM_SMELLY_LEVEL(IntEnum):
    """
    黑臭等级
    Black odor grade
    """
    EM_SMELLY_LEVEL_UNKNOWN = 0,                # 未知;Unknown;
    EM_SMELLY_LEVEL_NORMAL = 1,                 # 正常;normal;
    EM_SMELLY_LEVEL_LIGHT = 2,                  # 轻度污染;Light pollution;
    EM_SMELLY_LEVEL_HEAVY = 3,                  # 重度污染;Severe pollution;

class EM_FACEINFO_OPREATE_TYPE(IntEnum):
    """
    人脸信息记录操作类型
    the opreate type of face info
    """
    EM_FACEINFO_OPREATE_ADD = 0,                # 添加, pInbuf = NET_IN_ADD_FACE_INFO , pOutBuf = NET_OUT_ADD_FACE_INFO;add, pInbuf = NET_IN_ADD_FACE_INFO , pOutBuf = NET_OUT_ADD_FACE_INFO;
    EM_FACEINFO_OPREATE_GET = 1,                # 获取, pInBuf = NET_IN_GET_FACE_INFO , pOutBuf = NET_OUT_GET_FACE_INFO;get, pInBuf = NET_IN_GET_FACE_INFO , pOutBuf = NET_OUT_GET_FACE_INFO;
    EM_FACEINFO_OPREATE_UPDATE = 2,             # 更新, pInbuf = NET_IN_UPDATE_FACE_INFO , pOutBuf = NET_OUT_UPDATE_FACE_INFO;update, pInbuf = NET_IN_UPDATE_FACE_INFO , pOutBuf = NET_OUT_UPDATE_FACE_INFO;
    EM_FACEINFO_OPREATE_REMOVE = 3,             # 删除, pInbuf = NET_IN_REMOVE_FACE_INFO , pOutBuf = NET_OUT_REMOVE_FACE_INFO;remove, pInbuf = NET_IN_REMOVE_FACE_INFO , pOutBuf = NET_OUT_REMOVE_FACE_INFO;
    EM_FACEINFO_OPREATE_CLEAR = 4,              # 清除, pInbuf = NET_IN_CLEAR_FACE_INFO, pOutBuf = NET_OUT_CLEAR_FACE_INFO;clear, pInbuf = NET_IN_CLEAR_FACE_INFO, pOutBuf = NET_OUT_CLEAR_FACE_INFO;
    EM_FACEINFO_OPREATE_GETFACEEIGEN = 5,       # 获取人脸特征值, pInbuf = NET_IN_GETFACEEIGEN_INFO, pOutBuf = NET_OUT_GETFACEEIGEN_INFO;get face eigen, pInbuf = NET_IN_GETFACEEIGEN_INFO, pOutBuf = NET_OUT_GETFACEEIGEN_INFO;

class EM_A_NET_EM_OSD_BLEND_TYPE(IntEnum):
    """
    叠加类型
    Overlay Type
    """
    NET_EM_OSD_BLEND_TYPE_UNKNOWN = 0,          # 未知叠加类型;unknow overlay type;
    NET_EM_OSD_BLEND_TYPE_MAIN = 1,             # 叠加到主码流;Overlay to main stream;
    NET_EM_OSD_BLEND_TYPE_EXTRA1 = 2,           # 叠加到辅码流1;Overlay to extra stream 1;
    NET_EM_OSD_BLEND_TYPE_EXTRA2 = 3,           # 叠加到辅码流2;Overlay to extra stream 2;
    NET_EM_OSD_BLEND_TYPE_EXTRA3 = 4,           # 叠加到辅码流3;Overlay to extra stream 3;
    NET_EM_OSD_BLEND_TYPE_SNAPSHOT = 5,         # 叠加到抓图;Overlay to snap;
    NET_EM_OSD_BLEND_TYPE_PREVIEW = 6,          # 叠加到预览视频;Overlay to preview mode;

class EM_TITLE_TEXT_ALIGNTYPE(IntEnum):
    """
    标题文本对齐方式
    title text alignment type
    """
    EM_TEXT_ALIGNTYPE_INVALID = 0,              # 无效的对齐方式;Invalid alignment mathod;
    EM_TEXT_ALIGNTYPE_LEFT = 1,                 # 左对齐;Left alignment;
    EM_TEXT_ALIGNTYPE_XCENTER = 2,              # X坐标中对齐;X coordinate alignment;
    EM_TEXT_ALIGNTYPE_YCENTER = 3,              # Y坐标中对齐;Y coordinate alignment;
    EM_TEXT_ALIGNTYPE_CENTER = 4,               # 居中;Center;
    EM_TEXT_ALIGNTYPE_RIGHT = 5,                # 右对齐;Right alignment;
    EM_TEXT_ALIGNTYPE_TOP = 6,                  # 按照顶部对齐;By top alignment;
    EM_TEXT_ALIGNTYPE_BOTTOM = 7,               # 按照底部对齐;By bottom alignment;
    EM_TEXT_ALIGNTYPE_LEFTTOP = 8,              # 按照左上角对齐;By upper left alignment;
    EM_TEXT_ALIGNTYPE_CHANGELINE = 9,           # 换行对齐;Next row alignment;

class EM_A_NET_EM_TITLE_TYPE(IntEnum):
    """
    叠加标题用途
    Overlapping heading purpose
    """
    NET_EM_TITLE_UNKNOWN = 0,                   # 未知;Unknown;
    NET_EM_TITLE_RTINFO = 1,                    # 实时刻录信息;Real-time recording information;
    NET_EM_TITLE_CUSTOM = 2,                    # 自定义叠加、温湿度叠加; Overlay, Temperature and Humidity Overlay;
    NET_EM_TITLE_TITLE = 3,                     # 片头信息;Headline information;
    NET_EM_TITLE_CHECK = 4,                     # 校验码;Check code;
    NET_EM_TITLE_SPEEDOMETER = 5,               # 测速仪;Velocimeter;
    NET_EM_TITLE_GEOGRAPHY = 6,                 # 地理信息;geographic information;
    NET_EM_TITLE_ATMCARDINFP = 7,               # ATM卡号信息;ATM Card Number Information;
    NET_EM_TITLE_CAMERAID = 8,                  # 摄像机编号;Camera number;

class EM_SD_LOCK_STATE(IntEnum):
    """
    SD卡加锁状态
    """
    EM_SD_LOCK_STATE_UNKNOWN = -1,              # 未知;
    EM_SD_LOCK_STATE_NORMAL = 0,                # 未进行过加锁的状态, 如出厂状态，或清除密码时状态;
    EM_SD_LOCK_STATE_LOCKED = 1,                # 加锁;
    EM_SD_LOCK_STATE_UNLOCKED = 2,              # 未加锁（加锁后解锁）;

class EM_SD_ENCRYPT_FLAG(IntEnum):
    """
    SD卡加密功能标识
    """
    EM_SD_ENCRYPT_UNKNOWN = -1,                 # 未知;
    EM_SD_ENCRYPT_UNSUPPORT = 0,                # 设备不支持SD卡加密功能;
    EM_SD_ENCRYPT_SUPPORT_AND_GETDATA_SUCCESS = 1,    # 支持SD卡加密功能且获取数据成功;
    EM_SD_ENCRYPT_SUPPORT_AND_GETDATA_FAIL = 2, # 支持SD卡加密功能但获取数据失败;

class EM_STORAGE_HEALTH_TYPE(IntEnum):
    """
    健康状态标识
    """
    EM_STORAGE_HEALTH_UNKNOWN = -1,             # 未知;
    EM_STORAGE_HEALTH_UNSUPPORT = 0,            # 设备不支持健康检测功能;
    EM_STORAGE_HEALTH_SUPPORT_AND_SUCCESS = 1,  # 支持健康检测功能且获取数据成功;
    EM_STORAGE_HEALTH_SUPPORT_AND_FAIL = 2,     # 支持健康检测功能但获取数据失败;

class EM_STORAGE_DEVICE_STATUS(IntEnum):
    """
    存储设备状态
    """
    EM_STORAGE_DEVICE_UNKNOWN = 0,              # 未知;
    EM_STORAGE_DEVICE_ERROR = 1,                # 获取设备失败;
    EM_STORAGE_DEVICE_INITIALIZING = 2,         # 正在读取设备;
    EM_STORAGE_DEVICE_SUCCESS = 3,              # 获取设备成功;

class EM_PARTITION_TYPE(IntEnum):
    """
    分区类型
    """
    EM_PARTITION_UNKNOWN = 0,                   # 未知;
    EM_PARTITION_READ_WIRTE = 1,                # 读写;
    EM_PARTITION_READ_ONLY = 2,                 # 只读;
    EM_PARTITION_READ_GENERIC = 3,              # 一般的;

class EM_DETECTOR_STATUS_TYPE(IntEnum):
    """
    探测器状态类型
    Detector status type
    """
    EM_DETECTOR_STATUS_UNKNOWN = -1,            # 未知;unknown;
    EM_DETECTOR_STATUS_ALLFUNCT_ENABLE = 0,     # 启用所有功能;enable all functions;
    EM_DETECTOR_STATUS_ANTITAMPER_DISABLE = 1,  # 禁用防拆功能;unable anti disassembly function;
    EM_DETECTOR_STATUS_ALLFUNCT_DISABLE = 2,    # 禁用所有功能;unable all functions;

class EM_ACCESSORY_VOLUME(IntEnum):
    """
    设备布撤防时音量
    Volume of equipment during arming and disarming
    """
    EM_ACCESSORY_VOLUME_UNKNOWN = 0,            # 未知;unknown;
    EM_ACCESSORY_VOLUME_LOW = 1,                # 低音量;low volume;
    EM_ACCESSORY_VOLUME_MEDIUM = 2,             # 中音量;medium volume;
    EM_ACCESSORY_VOLUME_HIGH = 3,               # 高音量;high volume;

class EM_ACCESSORY_SENSITIVITY(IntEnum):
    """
    灵敏度
    Sensitivity
    """
    EM_ACCESSORY_SENSITIVITY_UNKNOWN = 0,       # 未知;unknown;
    EM_ACCESSORY_SENSITIVITY_LOW = 1,           # 低灵敏度;low sensitivity;
    EM_ACCESSORY_SENSITIVITY_MEDIUM = 2,        # 中灵敏度;medium sensitivity;
    EM_ACCESSORY_SENSITIVITY_HIGH = 3,          # 高灵敏度;high sensitivity;

class EM_POWER_REGULATION_TYPE(IntEnum):
    """
    功率调节类型
    Power regulation type
    """
    EM_POWER_REGULATION_UNKNOWN = -1,           # 未知;unknown;
    EM_POWER_REGULATION_AUTO = 0,               # 自动;auto;
    EM_POWER_REGULATION_LOW = 1,                # 低;low;
    EM_POWER_REGULATION_MEDIUM = 2,             # 中;medium;
    EM_POWER_REGULATION_HIGH = 3,               # 高;high;

class EM_ONLINE_STATUS(IntEnum):
    """
    在线状态
    Online status
    """
    EM_ONLINE_UNKNOWN = 0,                      # 未知;unknown;
    EM_ONLINE_OFF = 1,                          # 离线;offline;
    EM_ONLINE_ON = 2,                           # 在线;online;

class EM_ACCESSORY_ALARM_TYPE(IntEnum):
    """
    报警类型
    Alarm type
    """
    EM_ACCESSORY_ALARM_UNKNOWN = -1,            # 未知;unknown;
    EM_ACCESSORY_ALARM_INTRUSION = 0,           # 入侵;intrusion;
    EM_ACCESSORY_ALARM_FIRE = 1,                # 火警;fire alarm;
    EM_ACCESSORY_ALARM_MEDICAL = 2,             # 医疗;medical care;
    EM_ACCESSORY_ALARM_PANIC = 3,               # 紧急;panic;
    EM_ACCESSORY_ALARM_GAS = 4,                 # 燃气;gas;
    EM_ACCESSORY_ALARM_HOLDUP = 5,              # 双按钮紧急按钮报警类型;emergency button;

class EM_ACCESSORY_INPUT_TYPE(IntEnum):
    """
    输入类型
    Input type
    """
    EM_ACCESSORY_INPUT_UNKNOWN = -1,            # 未知;unknown;
    EM_ACCESSORY_INPUT_TAMPER = 0,              # 防拆;anti disassembly;
    EM_ACCESSORY_INPUT_SENSOR = 1,              # 报警输入;alarm input;

class EM_LED_BRIGHTNESS_LEVEL(IntEnum):
    """
    led灯亮度
    LED brightness
    """
    EM_LED_BRIGHTNESS_UNKNOWN = -1,             # 未知;unknown;
    EM_LED_BRIGHTNESS_CLOSED = 0,               # 关闭;close;
    EM_LED_BRIGHTNESS_LOW = 1,                  # 亮度最低;low brightness;
    EM_LED_BRIGHTNESS_MEDIUM = 2,               # 亮度适中;medium brightness;
    EM_LED_BRIGHTNESS_HIGH = 3,                 # 亮度最高;high brightness;

class EM_OPERATION_MODE(IntEnum):
    """
    操作模式
    Operating mode
    """
    EM_OPERATION_UNKNOWN = -1,                  # 未知;unknown;
    EM_OPERATION_PANIC = 0,                     # 紧急操作;Emergency operation;
    EM_OPERATION_CONTROL = 1,                   # 控制操作;Control operation;
    EM_OPERATION_MUTE_FIRE_ALARM = 2,           # 静音火灾报警操作;Silent fire alarm operation;

class EM_ANTI_MISPRESS_TYPE(IntEnum):
    """
    防误按模式
    Anti mispress mode
    """
    EM_ANTI_MISPRESS_UNKNOWN = 0,               # 未知;unknown;
    EM_ANTI_MISPRESS_OFF = 1,                   # 按下0.1s生效;press 0.1s to take effect;
    EM_ANTI_MISPRESS_LONG = 2,                  # 长按3s有效;long press for 3s;
    EM_ANTI_MISPRESS_DOUBLE = 3,                # 间断1s内连续按2次;press twice continuously within 1s;

class EM_EXPOWER_STATE(IntEnum):
    """
    外接电源状态
    External power status
    """
    EM_EXPOWER_DISCONNECT = 0,                  # 未连接;disconnect;
    EM_EXPOWER_CONNECT = 1,                     # 连接;connect;
    EM_EXPOWER_UNKNOWN = 2,                     # 未知;unknown;

class EM_RELAY_TYPE(IntEnum):
    """
    是否启用中继转发
    Enable relay forwarding
    """
    EM_RELAY_UNKNOWN = -1,                      # 未知;unknown;
    EM_RELAY_CLOSED = 0,                        # 关闭;closed;
    EM_RELAY_MANUAL = 1,                        # 手动;manual;
    EM_RELAY_AUTO = 2,                          # 自动;auto;

class EM_A_CAPTURE_SIZE(IntEnum):
    """
    分辨率枚举,供DSP_ENCODECAP使用
    Resolution enumeration. For DSP_ENCODECAP to use
    """
    CAPTURE_SIZE_D1 = 0,                        # 704*576(PAL) 704*480(NTSC),兼容WWxHH,下同;704*576(PAL) 704*480(NTSC),compatible WWxHH,the same below;
    CAPTURE_SIZE_HD1 = 1,                       # 352*576(PAL) 352*480(NTSC);352*576(PAL) 352*480(NTSC);
    CAPTURE_SIZE_BCIF = 2,                      # 704*288(PAL) 704*240(NTSC);704*288(PAL) 704*240(NTSC);
    CAPTURE_SIZE_CIF = 3,                       # 352*288(PAL) 352*240(NTSC);352*288(PAL) 352*240(NTSC);
    CAPTURE_SIZE_QCIF = 4,                      # 176*144(PAL) 176*120(NTSC);176*144(PAL) 176*120(NTSC);
    CAPTURE_SIZE_VGA = 5,                       # 640*480;640*480;
    CAPTURE_SIZE_QVGA = 6,                      # 320*240;320*240;
    CAPTURE_SIZE_SVCD = 7,                      # 480*480;480*480;
    CAPTURE_SIZE_QQVGA = 8,                     # 160*128;160*128;
    CAPTURE_SIZE_SVGA = 9,                      # 800*592;800*592;
    CAPTURE_SIZE_XVGA = 10,                     # 1024*768;1024*768;
    CAPTURE_SIZE_WXGA = 11,                     # 1280*800;1280*800;
    CAPTURE_SIZE_SXGA = 12,                     # 1280*1024;1280*1024;
    CAPTURE_SIZE_WSXGA = 13,                    # 1600*1024;1600*1024;
    CAPTURE_SIZE_UXGA = 14,                     # 1600*1200;1600*1200;
    CAPTURE_SIZE_WUXGA = 15,                    # 1920*1200;1920*1200;
    CAPTURE_SIZE_LTF = 16,                      # 240*192,ND1;240*192;
    CAPTURE_SIZE_720 = 17,                      # 1280*720;1280*720;
    CAPTURE_SIZE_1080 = 18,                     # 1920*1080;1920*1080;
    CAPTURE_SIZE_1_3M = 19,                     # 1280*960;1280*960;
    CAPTURE_SIZE_2M = 20,                       # 1872*1408,2_5M;1872*1408;
    CAPTURE_SIZE_5M = 21,                       # 3744*1408;3744*1408;
    CAPTURE_SIZE_3M = 22,                       # 2048*1536;2048*1536;
    CAPTURE_SIZE_5_0M = 23,                     # 2432*2050;2432*2050;
    CPTRUTE_SIZE_1_2M = 24,                     # 1216*1024;1216*1024;
    CPTRUTE_SIZE_1408_1024 = 25,                # 1408*1024;1408*1024;
    CPTRUTE_SIZE_8M = 26,                       # 3296*2472;3296*2472;
    CPTRUTE_SIZE_2560_1920 = 27,                # 2560*1920(5_1M);2560*1920(5M);
    CAPTURE_SIZE_960H = 28,                     # 960*576(PAL) 960*480(NTSC);960*576(PAL) 960*480(NTSC);
    CAPTURE_SIZE_960_720 = 29,                  # 960*720;960*720;
    CAPTURE_SIZE_NHD = 30,                      # 640*360;640*360;
    CAPTURE_SIZE_QNHD = 31,                     # 320*180;320*180;
    CAPTURE_SIZE_QQNHD = 32,                    # 160*90;160*90;
    CAPTURE_SIZE_960_540 = 33,                  # 960*540;960*540;
    CAPTURE_SIZE_640_352 = 34,                  # 640*352;640*352;
    CAPTURE_SIZE_640_400 = 35,                  # 640*400;640*400;
    CAPTURE_SIZE_320_192 = 36,                  # 320*192;320*192;
    CAPTURE_SIZE_320_176 = 37,                  # 320*176;320*176;
    CAPTURE_SIZE_SVGA1 = 38,                    # 800*600;800*600;
    CAPTURE_SIZE_2560_1440 = 39,                # 2560*1440;2560*1440;
    CAPTURE_SIZE_2304_1296 = 40,                # 2304*1296;2304*1296;
    CAPTURE_SIZE_2592_1520 = 41,                # 2592*1520;2592*1520;
    CAPTURE_SIZE_4000_3000 = 42,                # 4000*3000;4000*3000;
    CAPTURE_SIZE_2880_2880 = 43,                # 2880*2880;2880*2880;
    CAPTURE_SIZE_2880_2160 = 44,                # 2880*2160;2880*2160;
    CAPTURE_SIZE_2688_1520 = 45,                # 2688*1520;2688*1520;
    CAPTURE_SIZE_2592_1944 = 46,                # 2592*1944;2592*1944;
    CAPTURE_SIZE_3072_1728 = 47,                # 3072*1728;3072*1728;
    CAPTURE_SIZE_3072_2048 = 48,                # 3072*2048;3072*2048;
    CAPTURE_SIZE_3840_2160 = 49,                # 3840*2160;3840*2160;
    CAPTURE_SIZE_NR = 255,

class EM_EXTERNAL_WIFI_PRIORITY(IntEnum):
    """
    外部wifi优先级
    External WiFi priority
    """
    EM_EXTERNAL_WIFI_UNKNOWN = 0,               # 未知;unknown;
    EM_EXTERNAL_WIFI_FIRST = 1,                 # 首选外部wifi;preferred external WiFi;
    EM_EXTERNAL_WIFI_ALTERNATIVE = 2,           # 备选外部wifi;optional external WiFi;
    EM_EXTERNAL_WIFI_USEONLY = 3,               # 仅使用外部wifi;use external WiFi only;

class EM_ARMING_TYPE(IntEnum):
    """
    布防模式
    Arming mode
    """
    EM_ARMING_UNKNOWN = -1,                     # 未知;unknown;
    EM_ARMING_ATHOME = 0,                       # 在家布防;arming at home;
    EM_ARMING_OUT = 1,                          # 外出布防;arming outside;

class EM_BUTTON_ALARM_TYPE(IntEnum):
    """
    按钮报警类型
    Alarm type of button
    """
    EM_BUTTON_ALARM_UNKNOWN = -1,               # 未知;unknown;
    EM_BUTTON_ALARM_FIRE = 0,                   # 火警;fire alarm;
    EM_BUTTON_ALARM_EMERGENCY = 1,              # 紧急报警;emergency alarm;
    EM_BUTTON_ALARM_MEDICAL = 2,                # 医疗报警;medical alarm;

class EM_A_NET_EM_POWER_TYPE(IntEnum):
    """
    供电类型
    """
    NET_EM_POWER_TYPE_UNKNOWN = -1,             # 未知;
    NET_EM_POWER_TYPE_POWERADAPTER = 0,         # 电源适配器;
    NET_EM_POWER_TYPE_BATTERY = 1,              # 电池;
    NET_EM_POWER_TYPE_BATTERY_AND_POWERADAPTER = 2,    # 电池+电源适配器;

class EM_A_NET_EM_ETH_STATE(IntEnum):
    """
    有线网连接状态
    """
    NET_EM_ETH_UNKNOWN = 0,                     # 未知;
    NET_EM_ETH_CONNECT = 1,                     # 连接;
    NET_EM_ETH_DISCONNECT = 2,                  # 未连接;

class EM_A_NET_EM_SIM_STATE(IntEnum):
    """
    sim卡状态
    """
    NET_EM_SIM_UNKNOWN = 0,                     # 未知;
    NET_EM_SIM_ONLINE = 1,                      # 在线;
    NET_EM_SIM_OFFLINE = 2,                     # 离线;

class EM_A_NET_EM_TAMPER_STATE(IntEnum):
    """
    主机防拆状态
    """
    NET_EM_TAMPER_UNKNOWN = -1,                 # 未知;
    NET_EM_TAMPER_NOALARM = 0,                  # 未报警;
    NET_EM_TAMPER_ALARMING = 1,                 # 报警中;

class EM_A_NET_EM_SNAP_TYPE(IntEnum):
    """
    抓图类型
    snap type
    """
    EM_SNAP_UNKNOWN = 0,                        # 未知类型;unknow;
    EM_SNAP_NORMAL = 1,                         # 普通抓图;normal;
    EM_SNAP_MOVEEXAMINE = 2,                    # 动检抓图;move examine;
    EM_SNAP_ALARM = 3,                          # 报警抓图;alarm;

class EM_A_NET_EM_FORMAT_TYPE(IntEnum):
    """
    码流类型
    the type of stream
    """
    EM_FORMAT_TYPE_UNKNOWN = 0,                 # 未知类型;unknow;
    EM_FORMAT_MAIN_NORMAL = 1,                  # 主码流普通编码;main stream--normal;
    EM_FORMAT_MAIN_MOVEEXAMINE = 2,             # 主码流动检编码;main stream--move examine;
    EM_FORMAT_MAIN_ALARM = 3,                   # 主码流报警编码;main stream--alarm;
    EM_FORMAT_EXTRA1 = 4,                       # 辅码流1;extra stream 1;
    EM_FORMAT_EXTRA2 = 5,                       # 辅码流2;extra stream 2;
    EM_FORMAT_EXTRA3 = 6,                       # 辅码流3;extra stream 3;

class EM_A_CFG_LINK_TYPE(IntEnum):
    """
    云台联动类型
    PTZ activation type
    """
    LINK_TYPE_NONE = 0,                         # 无联动;No activation;
    LINK_TYPE_PRESET = 1,                       # 联动预置点;Activate the preset;
    LINK_TYPE_TOUR = 2,                         # 联动巡航;Activate the tour;
    LINK_TYPE_PATTERN = 3,                      # 联动轨迹;Activate the pattern;

class EM_A_CFG_ATTACHMENT_TYPE(IntEnum):
    """
    邮件附件类型
    Mail attachment type
    """
    ATTACHMENT_TYPE_PIC = 0,                    # 图片附件;Picture attachment;
    ATTACHMENT_TYPE_VIDEO = 1,                  # 视频附件;Video attachment;
    ATTACHMENT_TYPE_NUM = 2,                    # 附件类型总数;Attachment;

class EM_A_CFG_SPLITMODE(IntEnum):
    """
    分割模式
    Split mode
    """
    SPLITMODE_1 = 1,                            # 1画面;1 picture;
    SPLITMODE_2 = 2,                            # 2画面;2 picture;
    SPLITMODE_4 = 4,                            # 4画面;4 picture;
    SPLITMODE_5 = 5,                            # 5画面;5 picture;
    SPLITMODE_6 = 6,                            # 6画面;6 picture;
    SPLITMODE_8 = 8,                            # 8画面;8 picture;
    SPLITMODE_9 = 9,                            # 9画面;9 picture;
    SPLITMODE_12 = 12,                          # 12画面;12 picture;
    SPLITMODE_16 = 16,                          # 16画面;16 picture;
    SPLITMODE_20 = 20,                          # 20画面;20 picture;
    SPLITMODE_25 = 25,                          # 25画面;25 picture;
    SPLITMODE_36 = 36,                          # 36画面;36 picture;
    SPLITMODE_64 = 64,                          # 64画面;64 picture;
    SPLITMODE_144 = 144,                        # 144画面;144 picture;
    SPLITMODE_PIP = 1000,                       # 画中画分割模式基础值;Picinpic segmentation model base value;
    SPLITMODE_PIP1 = 1001,                      # 画中画模式, 1个全屏大画面+1个小画面窗口;Picinpic type, a full screen image + 1 small screen window;
    SPLITMODE_PIP3 = 1003,                      # 画中画模式, 1个全屏大画面+3个小画面窗口;Picinpic type, a full screen image + 3 small screen window;
    SPLITMODE_FREE = 2000,                      # 自由开窗模式，可以自由创建、关闭窗口，自由设置窗口位置和Z轴次序;Free window mode, can freely create close the window, free settings window corresponding to the Z axis;
    SPLITMODE_COMPOSITE_1 = 3001,               # 融合屏成员1分割;Panel member 1 segmentation;
    SPLITMODE_COMPOSITE_4 = 3004,               # 融合屏成员4分割;Panel member 4 segmentation;
    SPLITMODE_3 = 10,                           # 3画面;3 picture;
    SPLITMODE_3B = 11,                          # 3画面倒品;3 picture(bottom);
    SPLITMODE_EOF = 12,                         # 结束标识;The end;

class EM_CFG_ACCESSCONTROLTYPE(IntEnum):
    """
    门禁操作类型
    Entrance Guard Operation Type
    """
    EM_CFG_ACCESSCONTROLTYPE_NULL = 0,          # 不做操作;Do not operate;
    EM_CFG_ACCESSCONTROLTYPE_AUTO = 1,          # 自动;Automatic;
    EM_CFG_ACCESSCONTROLTYPE_OPEN = 2,          # 开门;Open the Door;
    EM_CFG_ACCESSCONTROLTYPE_CLOSE = 3,         # 关门;Close the Door;
    EM_CFG_ACCESSCONTROLTYPE_OPENALWAYS = 4,    # 永远开启;Open Always;
    EM_CFG_ACCESSCONTROLTYPE_CLOSEALWAYS = 5,   # 永远关闭;Close Always;

class EM_CALLER_TYPE(IntEnum):
    """
    语音呼叫发起方
    Voice Calls Originating
    """
    EM_CALLER_DEVICE = 0,                       # 设备发起;Device Originating;

class EM_CALLER_PROTOCOL_TYPE(IntEnum):
    """
    呼叫协议
    Call Protocol
    """
    EM_CALLER_PROTOCOL_CELLULAR = 0,            # 手机方式;Phone Mode;

class EM_BATTERY_POWER_ALARM_MODE(IntEnum):
    """
    电量报警模式
    Battery power alarm mode
    """
    EM_BATTERY_POWER_ALARM_MODE_UNKNOWN = -1,   # 未知;unknown;
    EM_BATTERY_POWER_ALARM_MODE_MANUAL = 0,     # 手动;manual;
    EM_BATTERY_POWER_ALARM_MODE_AUTO = 1,       # 自动;auto;

class EM_PTZ_LINK_TYPE(IntEnum):
    """
    联动类型
    Ptz link type
    """
    EM_PTZ_LINK_TYPE_NONE = 0,                  # none;none;
    EM_PTZ_LINK_TYPE_PRESET = 1,                # "Preset" 联动预置点;"Preset";
    EM_PTZ_LINK_TYPE_TOUR = 2,                  # "Tour" 联动巡航;"Tour";
    EM_PTZ_LINK_TYPE_PATTERN = 3,               # "Pattern" 联动模式;"Pattern";
    EM_PTZ_LINK_TYPE_ZOOM = 4,                  # "Zoom" 联动变倍;"Zoom";
    EM_PTZ_LINK_TYPE_SINGLESCENE = 5,           # "SingleScene" 联动智能单场景;"SingleScene";
    EM_PTZ_LINK_TYPE_QUICKFOCUS = 6,            # "QuickFocus" 热成像云台联动快速定位;"QuickFocus";

class EM_A_SPLIT_MODE(IntEnum):
    """
    分割模式
    Split mode
    """
    EM_A_SPLIT_1 = 1,                           # 1画面;1-window;
    EM_A_SPLIT_2 = 2,                           # 2画面;2-window;
    EM_A_SPLIT_4 = 4,                           # 4画面;4-window;
    EM_A_SPLIT_5 = 5,                           # 5画面;5-window;
    EM_A_SPLIT_6 = 6,                           # 6画面;6-window;
    EM_A_SPLIT_8 = 8,                           # 8画面;8-window;
    EM_A_SPLIT_9 = 9,                           # 9画面;9-window;
    EM_A_SPLIT_12 = 12,                         # 12画面;12-window;
    EM_A_SPLIT_16 = 16,                         # 16画面;16-window;
    EM_A_SPLIT_20 = 20,                         # 20画面;20-window;
    EM_A_SPLIT_25 = 25,                         # 25画面;25-window;
    EM_A_SPLIT_36 = 36,                         # 36画面;36-window;
    EM_A_SPLIT_64 = 64,                         # 64画面;64-window;
    EM_A_SPLIT_144 = 144,                       # 144画面;144-window;
    EM_A_PIP_1 = 1001,                          # 画中画模式, 1个全屏大画面+1个小画面窗口;PIP mode.1-full screen+1-small window;
    EM_A_PIP_3 = 1003,                          # 画中画模式, 1个全屏大画面+3个小画面窗口;PIP mode.1-full screen+3-small window;
    EM_A_SPLIT_FREE = 2000,                     # 自由开窗模式,可以自由创建、关闭窗口,自由设置窗口位置和Z轴次序;free open window mode,are free to create,close, window position related to the z axis;
    EM_A_COMPOSITE_SPLIT_1 = 3001,              # 融合屏成员1分割;integration of a split screen;
    EM_A_COMPOSITE_SPLIT_4 = 3004,              # 融合屏成员4分割;fusion of four split screen;
    EM_A_SPLIT_3 = 10,                          # 3画面;3-window;
    EM_A_SPLIT_3B = 11,                         # 3画面倒品;3-window(bottom);
    EM_A_SPLIT_4A = 4001,                       # 4个画面, 一个大画面在左边，3个小画面在右边排成一列;4-window, 1 big on the left, 3 samll on the right in a row;

class EM_A_NET_EM_FILCKERLIGHT_TYPE(IntEnum):
    """
    闪烁灯光类型
    Flashing light type
    """
    NET_EM_WHITELIGHT = 0,                      # 闪烁白光灯;white light;
    NET_EM_REDBLUELIGHT = 1,                    # 红蓝闪烁警示灯;red blue light;

class EM_A_NET_EM_LIGHTLINK_TYPE(IntEnum):
    """
    灯光联动方式
    Lighting linkage mode
    """
    NET_EM_FILCKER = 0,                         # 闪烁； 默认;filcker;
    NET_EM_KEEPLIGHTING = 1,                    # 常亮;keep lighting;

class EM_MEDIA_GLOBAL_SNAP_FORMAT_AS(IntEnum):
    """
    抓图流编码格式参照格式
    Snap format reference;
    """
    EM_MEDIA_GLOBAL_SNAP_FORMAT_AS_UNKNOWN = 0,
    EM_MEDIA_GLOBAL_SNAP_FORMAT_AS_MAIN_FORMAT = 1,    # 参照主码流;refer to main stream;
    EM_MEDIA_GLOBAL_SNAP_FORMAT_AS_EXTRA_FORMAT = 2,    # 参照辅码流1;refer to sub stream1;
    EM_MEDIA_GLOBAL_SNAP_FORMAT_AS_EXTRA2_FORMAT = 3,    # 参照辅码流2;refer to sub stream2;
    EM_MEDIA_GLOBAL_SNAP_FORMAT_AS_EXTRA3_FORMAT = 4,    # 参照辅码流3;refer to sub stream3;

class EM_SMART_MOTION_DETECT_SENSITIVITY_LEVEL(IntEnum):
    """
    智能动检敏感等级
    Sensitivity level of intelligent dynamic inspection
    """
    EM_SMART_MOTION_DETECT_SENSITIVITY_LEVEL_UNKNOWN = 0,    # 未知;Unknown;
    EM_SMART_MOTION_DETECT_SENSITIVITY_LEVEL_LOW = 1,    # 低;Low;
    EM_SMART_MOTION_DETECT_SENSITIVITY_LEVEL_MIDDLE = 2,    # 中;Middle;
    EM_SMART_MOTION_DETECT_SENSITIVITY_LEVEL_HIGH = 3,    # 高;High;

class EM_SENSE_METHOD(IntEnum):
    """
    传感器感应方式枚举类型
    Enumeration Type Sensor Sensing Way
    """
    EM_SENSE_UNKNOWN = -1,                      # 未知类型;Unknown type;
    EM_SENSE_DOOR = 0,                          # 门磁;Magnetic Door;
    EM_SENSE_PASSIVEINFRA = 1,                  # 被动红外;Passive Infrared;
    EM_SENSE_GAS = 2,                           # 气感;Gas Sense;
    EM_SENSE_SMOKING = 3,                       # 烟感;Smoking Sense;
    EM_SENSE_WATER = 4,                         # 水感;Water Sense;
    EM_SENSE_ACTIVEFRA = 5,                     # 主动红外;Active Infrared;
    EM_SENSE_GLASS = 6,                         # 玻璃破碎;Glass Broken;
    EM_SENSE_EMERGENCYSWITCH = 7,               # 紧急开关;EMERGENCY SWITCH;
    EM_SENSE_SHOCK = 8,                         # 震动;Shock;
    EM_SENSE_DOUBLEMETHOD = 9,                  # 双鉴(红外+微波);Double Method(Infrared+Microwave);
    EM_SENSE_THREEMETHOD = 10,                  # 三技术;Three Method;
    EM_SENSE_TEMP = 11,                         # 温度;Temperature;
    EM_SENSE_HUMIDITY = 12,                     # 湿度;Humidity;
    EM_SENSE_WIND = 13,                         # 风速;Wind;
    EM_SENSE_CALLBUTTON = 14,                   # 呼叫按钮;Call Button;
    EM_SENSE_GASPRESSURE = 15,                  # 气体压力;Gas Pressure;
    EM_SENSE_GASCONCENTRATION = 16,             # 燃气浓度;Gas Concentration;
    EM_SENSE_GASFLOW = 17,                      # 气体流量;Gas Flow;
    EM_SENSE_OIL = 18,                          # 油量检测;Oil;
    EM_SENSE_MILEAGE = 19,                      # 里程数检测;Mileage;
    EM_SENSE_OTHER = 20,                        # 其他;Other;
    EM_SEHSE_CO2 = 21,                          # 二氧化碳浓度检测;Determination of CO2;
    EM_SEHSE_SOUND = 22,                        # 噪音检测;Noise detection;
    EM_SEHSE_PM25 = 23,                         # PM2.5检测;PM2.5 detection;
    EM_SEHSE_SF6 = 24,                          # 六氟化硫浓度检测;Determination of SF6;
    EM_SEHSE_O3 = 25,                           # 臭氧;O3;
    EM_SEHSE_AMBIENTLIGHT = 26,                 # 环境光照检测;ambient light detection;
    EM_SEHSE_INFRARED = 27,                     # 红外报警;infra red;
    EM_SEHSE_TEMP1500 = 28,                     # 1500温度传感器;temp 1500;
    EM_SEHSE_TEMPDS18B20 = 29,                  # DS18B20温度传感器;temp DS18B20;
    EM_SEHSE_HUMIDITY1500 = 30,                 # 1500湿度传感器;humidity 1500;
    EM_SEHSE_URGENCYBUTTON = 31,                # 紧急按钮;urgency button;
    EM_SEHSE_STEAL = 32,                        # 盗窃;steal;
    EM_SEHSE_PERIMETER = 33,                    # 周界;perimeter;
    EM_SEHSE_PREVENTREMOVE = 34,                # 防拆;prevent remove;
    EM_SEHSE_DOORBELL = 35,                     # 门铃;doorbell;
    EM_SEHSE_ALTERVOLT = 36,                    # 交流电压传感器;alter volt;
    EM_SEHSE_DIRECTVOLT = 37,                   # 直流电压传感器;direct volt;
    EM_SEHSE_ALTERCUR = 38,                     # 交流电流传感器;alter cur;
    EM_SEHSE_DIRECTCUR = 39,                    # 直流电流传感器;direct cur;
    EM_SEHSE_RSUGENERAL = 40,                   # 通用模拟量;general;
    EM_SEHSE_RSUDOOR = 41,                      # 门禁感应;door;
    EM_SEHSE_RSUPOWEROFF = 42,                  # 断电感应;power off;
    EM_SEHSE_CURTAINSENSOR = 43,                # 幕帘传感器;curtain sensor;
    EM_SEHSE_MOBILESENSOR = 44,                 # 移动传感器;mobile sensor;
    EM_SEHSE_FIREALARM = 45,                    # 火警;fire alarm;
    EM_SEHSE_LOCKTONGUE = 46,                   # 锁舌;lock tongue;
    EM_SENSE_NUM = 47,                          # 枚举类型总数,注意：这个值不能作为常量使用;The Total Number of Enumerated Types,notice:can not be used as a constant;

class EM_CTRL_ENABLE(IntEnum):
    """
    报警使能控制方式枚举类型
    Alarm control method
    """
    EM_CTRL_NORMAL = 0,                         # 不控制使能;No enable;
    EM_CTRL_ALWAYS_EN = 1,                      # 总是使能;Always enable;
    EM_CTRL_ONCE_DIS = 2,                       # 旁路;Bypass;
    EM_CTRL_ALWAYS_DIS = 3,                     # 移除;Disappear;
    EM_CTRL_NUM = 4,                            # 枚举类型总数;The total of enum type;

class EM_CFG_DEFENCEAREATYPE(IntEnum):
    """
    防区类型
    DefenceArea Type
    """
    EM_CFG_DefenceAreaType_Unknown = 0,         # 未知类型;unknown type;
    EM_CFG_DefenceAreaType_InTime = 1,          # 即时防区;instant zone;
    EM_CFG_DefenceAreaType_Delay = 2,           # 延时防区;delay zone;
    EM_CFG_DefenceAreaType_FullDay = 3,         # 24小时防区;24-hour zone;
    EM_CFG_DefenceAreaType_Follow = 4,          # 跟随防区;follow zone;
    EM_CFG_DefenceAreaType_Medical = 5,         # 医疗紧急防区;medical zone;
    EM_CFG_DefenceAreaType_Panic = 6,           # 恐慌防区;panic zone;
    EM_CFG_DefenceAreaType_Fire = 7,            # 火警防区;Fire zone;
    EM_CFG_DefenceAreaType_FullDaySound = 8,    # 24小时有声防区;24-hour sound zone;
    EM_CFG_DefenceAreaType_FullDaySlient = 9,   # 24小时无声防区;24-hour mute zone;
    EM_CFG_DefenceAreaType_Entrance1 = 10,      # 出入防区1;enter zone 1;
    EM_CFG_DefenceAreaType_Entrance2 = 11,      # 出入防区2;enter zone 2;
    EM_CFG_DefenceAreaType_InSide = 12,         # 内部防区;internal zone;
    EM_CFG_DefenceAreaType_OutSide = 13,        # 外部防区;external zone;
    EM_CFG_DefenceAreaType_PeopleDetect = 14,   # 人员检测防区;people detect zone;
    EM_CFG_DefenceAreaType_Robbery = 15,        # 匪警防区;Robbery zone;

class EM_RESTORE_TYPE(IntEnum):
    """
    接口CLIENT_ControlDevice类型 RESTOREDEFAULT, "恢复默认配置"掩码,可进行与、或操作,
    interface CLIENT_ControlDevice enum type RESTOREDEFAULT, Restore default setup mask. Can use to AND & OR operation
    """
    EM_RESTORE_COMMON = 0x00000001,             # General setup
    EM_RESTORE_CODING = 0x00000002,             # Encode setup
    EM_RESTORE_VIDEO = 0x00000004,              # Record setup
    EM_RESTORE_COMM = 0x00000008,               # COM setup
    EM_RESTORE_NETWORK = 0x00000010,            # network setup
    EM_RESTORE_ALARM = 0x00000020,              # Alarm setup
    EM_RESTORE_VIDEODETECT = 0x00000040,        # Video detection
    EM_RESTORE_PTZ = 0x00000080,                # PTZ control
    EM_RESTORE_OUTPUTMODE = 0x00000100,         # Output mode
    EM_RESTORE_CHANNELNAME = 0x00000200,        # Channel name
    EM_RESTORE_VIDEOINOPTIONS = 0x00000400,     # Camera attribute
    EM_RESTORE_CPS = 0x00000800,                # TrafficSnapshot
    EM_RESTORE_INTELLIGENT = 0x00001000,        # Intelligent Component
    EM_RESTORE_REMOTEDEVICE = 0x00002000,       # Remote device configuration
    EM_RESTORE_DECODERVIDEOOUT = 0x00004000,    # decode video out
    EM_RESTORE_LINKMODE = 0x00008000,           # link mode
    EM_RESTORE_COMPOSITE = 0x00010000,          # split screen
    EM_RESTORE_ALL = 0x80000000,                # Reset all

class EM_A_NET_DEVICE_TYPE(IntEnum):
    """
    设备类型
    Device type
    """
    NET_PRODUCT_NONE = 0,
    NET_DVR_NONREALTIME_MACE = 1,               # 非实时MACE;Non real-time MACE;
    NET_DVR_NONREALTIME = 2,                    # 非实时;Non real-time;
    NET_NVS_MPEG1 = 3,                          # 网络视频服务器;Network video server;
    NET_DVR_MPEG1_2 = 4,                        # MPEG1二路录像机;MPEG1 2-ch DVR;
    NET_DVR_MPEG1_8 = 5,                        # MPEG1八路录像机;MPEG1 8-ch DVR;
    NET_DVR_MPEG4_8 = 6,                        # MPEG4八路录像机;MPEG4 8-ch DVR;
    NET_DVR_MPEG4_16 = 7,                       # MPEG4十六路录像机;MPEG4 16-ch DVR;
    NET_DVR_MPEG4_SX2 = 8,                      # LB系列录像机;LB series DVR;
    NET_DVR_MEPG4_ST2 = 9,                      # GB系列录像机;GB series DVR;
    NET_DVR_MEPG4_SH2 = 10,                     # HB系列录像机 10;HB series DVR;
    NET_DVR_MPEG4_GBE = 11,                     # GBE系列录像机;GBE series DVR;
    NET_DVR_MPEG4_NVSII = 12,                   # II代网络视频服务器;II network video server;
    NET_DVR_STD_NEW = 13,                       # 新标准配置协议;New standard configuration protocol;
    NET_DVR_DDNS = 14,                          # DDNS服务器;DDNS server;
    NET_DVR_ATM = 15,                           # ATM机;ATM series;
    NET_NB_SERIAL = 16,                         # 二代非实时NB系列机器;2nd non real-time NB series DVR;
    NET_LN_SERIAL = 17,                         # LN系列产品;LN series;
    NET_BAV_SERIAL = 18,                        # BAV系列产品;BAV series;
    NET_SDIP_SERIAL = 19,                       # SDIP系列产品;SDIP series;
    NET_IPC_SERIAL = 20,                        # IPC系列产品 20;IPC series;
    NET_NVS_B = 21,                             # NVS B系列;NVS B series;
    NET_NVS_C = 22,                             # NVS H系列;NVS H series;
    NET_NVS_S = 23,                             # NVS S系列;NVS S series;
    NET_NVS_E = 24,                             # NVS E系列;NVS E series;
    NET_DVR_NEW_PROTOCOL = 25,                  # 从QueryDevState中查询设备类型,以字符串格式;Search device type from QueryDevState. it is in string format;
    NET_NVD_SERIAL = 26,                        # 解码器;NVD;
    NET_DVR_N5 = 27,                            # N5;N5;
    NET_DVR_MIX_DVR = 28,                       # 混合DVR;HDVR;
    NET_SVR_SERIAL = 29,                        # SVR系列;SVR series;
    NET_SVR_BS = 30,                            # SVR-BS 30;SVR-BS;
    NET_NVR_SERIAL = 31,                        # NVR系列;NVR series;
    NET_DVR_N51 = 32,                           # N51;N51;
    NET_ITSE_SERIAL = 33,                       # ITSE 智能分析盒;ITSE Intelligent Analysis Box;
    NET_ITC_SERIAL = 34,                        # 智能交通像机设备;Intelligent traffic camera equipment;
    NET_HWS_SERIAL = 35,                        # 雷达测速仪HWS;radar speedometer HWS;
    NET_PVR_SERIAL = 36,                        # 便携式音视频录像机;portable video record;
    NET_IVS_SERIAL = 37,                        # IVS（智能视频服务器系列）;IVS(intelligent video server series);
    NET_IVS_B = 38,                             # 通用智能视频侦测服务器;universal intelligent detect video server series;
    NET_IVS_F = 39,                             # 目标识别服务器;target recognisation server;
    NET_IVS_V = 40,                             # 视频质量诊断服务器 40;video quality diagnosis server;
    NET_MATRIX_SERIAL = 41,                     # 矩阵;matrix;
    NET_DVR_N52 = 42,                           # N52;N52;
    NET_DVR_N56 = 43,                           # N56;N56;
    NET_ESS_SERIAL = 44,                        # ESS;ESS;
    NET_IVS_PC = 45,                            # 人数统计服务器;number statistic server;
    NET_PC_NVR = 46,                            # pc-nvr;pc-nvr;
    NET_DSCON = 47,                             # 大屏控制器;screen controller;
    NET_EVS = 48,                               # 网络视频存储服务器;network video storage server;
    NET_EIVS = 49,                              # 嵌入式智能分析视频系统;an embedded intelligent video analysis system;
    NET_DVR_N6 = 50,                            # DVR-N6 50;DVR-N6;
    NET_UDS = 51,                               # 万能解码器;K-Lite Codec Pack;
    NET_AF6016 = 52,                            # 银行报警主机;Bank alarm host;
    NET_AS5008 = 53,                            # 视频网络报警主机;Video network alarm host;
    NET_AH2008 = 54,                            # 网络报警主机;Network alarm host;
    NET_A_SERIAL = 55,                          # 报警主机系列;Alarm host series;
    NET_BSC_SERIAL = 56,                        # 门禁系列产品;Access control series of products;
    NET_NVS_SERIAL = 57,                        # NVS系列产品;NVS series product;
    NET_VTO_SERIAL = 58,                        # VTO系列产品;VTO series product;
    NET_VTNC_SERIAL = 59,                       # VTNC系列产品;VTNC series product;
    NET_TPC_SERIAL = 60,                        # TPC系列产品, 即热成像设备 60;TPC series product, it is the thermal device;
    NET_ASM_SERIAL = 61,                        # 无线中继设备;ASM series product;
    NET_VTS_SERIAL = 62,                        # 管理机;VTS series product;
    NET_ARC2016C = 63,                          # 报警主机ARC2016C;Alarm host-ARC2016C;
    NET_ASA = 64,                               # 考勤机;ASA Attendance machine;
    NET_VTT_SERIAL = 65,                        # 行业对讲终端;Industry terminal walkie-talkie;
    NET_VTA_SERIAL = 66,                        # 报警柱;Alarm column;
    NET_VTNS_SERIAL = 67,                       # SIP服务器;SIP Server;
    NET_VTH_SERIAL = 68,                        # 室内机;Indoor unit;
    NET_IVSS = 69,                              # IVSS产品;IVSS;
    NET_ASG = 70,                               # 目标道闸;ASG;
    NET_RADAR = 71,                             # 雷达产品;Radar series;
    NET_RADAR_PTZ = 72,                         # 雷达系统;Radar SD;
    NET_RADAR_CAM = 73,                         # 摄像雷达;Radar IPC;
    NET_ASE = 74,                               # 梯控设备;lift controller;
    NET_XRAY_SERVER = 75,                       # 安检服务器;XRay Server;
    NET_XRAY_DEVICE = 76,                       # 安检一体机;XRay Device;
    NET_SECURITY_GATE = 77,                     # 安检门;Security Gate;
    NET_TS = 78,                                # 以太网交换机;Ethernet switch;
    NET_GP = 79,                                # 工牌相机;Industrial camera;
    NET_EAS = 80,                               # 商超防盗天线;Shangchao anti-theft antenna;

class EM_CFG_AREA_SUBTYPE(IntEnum):
    """
    区域测温的子类型
    Regional Temperature Monitoring subtypes
    """
    EM_CFG_AREA_SUBTYPE_UNKNOWN = 0,
    EM_CFG_AREA_SUBTYPE_RECT = 1,               # 矩形;Rect;
    EM_CFG_AREA_SUBTYPE_ELLIPSE = 2,            # 椭圆;Ellipse;
    EM_CFG_AREA_SUBTYPE_POLYGON = 3,            # 多边形;Polygon;

class EM_STREAM_POLICY(IntEnum):
    """
    带宽不足时码流策略
    Bit stream strategy when bandwitch is insufficient
    """
    STREAM_POLICY_UNKNOWN = 0,
    STREAM_POLICY_NONE = 1,                     # 无策略,不开启使能"None";No strategy, diable "None";
    STREAM_POLICY_QUALITY = 2,                  # 画质优先"Quality";Qualiy first "Quality";
    STREAM_POLICY_FLUENCY = 3,                  # 流畅度优先"Fluency";Fliency first"Fluency";
    STREAM_POLICY_AUTOADAPT = 4,                # 自动"AutoAdapt";Auto "AutoAdapt";

class EM_CFG_SENDPOLICY(IntEnum):
    """
    上传策略
    Send Policy
    """
    EM_SNEDPOLICY_UNKNOWN = -1,
    EM_SENDPOLICY_TIMING = 0,                   # 定时上报;Regular reporting;
    EM_SENDPOLICY_EVENT = 1,                    # 事件触发上报;Event triggered report;

class EM_SMARTHOME_SCENE_MODE(IntEnum):
    """
    智能家居情景模式
    SmartHome scene mode
    """
    EM_SMARTHOME_SCENE_MODE_UNKNOWN = 0,        # 未知;Unknown;
    EM_SMARTHOME_SCENE_MODE_AT_HOME = 1,        # 在家;At home;
    EM_SMARTHOME_SCENE_MODE_LEAVE_HOME = 2,     # 离开;Leave home;
    EM_SMARTHOME_SCENE_MODE_IN_SLEEPING = 3,    # 睡眠;In sleeping;

class EM_A_NET_NOTIFY_TYPE(IntEnum):
    """
    通知类型
    Notify type
    """
    NET_NOTIFY_TYPE_UNKNOWN = 0,                # 未知;unknown;
    NET_NOTIFY_TYPE_SMS = 1,                    # 短信;message, SMS;
    NET_NOTIFY_TYPE_CALL = 2,                   # 电话;phone call;
    NET_NOTIFY_TYPE_ALL = 3,                    # 短信&电话;SMS&CALL;

class EM_A_LOG_QUERY_TYPE(IntEnum):
    """
    日志查询类型
    Log search type
    """
    EM_A_LOG_ALL = 0,                           # 所有日志;All logs;
    EM_A_LOG_SYSTEM = 1,                        # 系统日志;System logs;
    EM_A_LOG_CONFIG = 2,                        # 配置日志;Configuration logs;
    EM_A_LOG_STORAGE = 3,                       # 存储相关;Storage logs;
    EM_A_LOG_ALARM = 4,                         # 报警日志;Alarm logs;
    EM_A_LOG_RECORD = 5,                        # 录象相关;Record related;
    EM_A_LOG_ACCOUNT = 6,                       # 帐号相关;Account related;
    EM_A_LOG_CLEAR = 7,                         # 清除日志;Clear log;
    EM_A_LOG_PLAYBACK = 8,                      # 回放相关;Playback related;
    EM_A_LOG_MANAGER = 9,                       # 前端管理运行相关;Concerning the front-end management and running;

class EM_CFG_WIRELESS_AUTHENTICATION(IntEnum):
    """
    无线设备认证方式
    wireless Authentication
    """
    EM_CFG_WIRELESS_AUTHENTICATION_UNKNOWN = 0, # UnKnown;UnKnown;
    EM_CFG_WIRELESS_AUTHENTICATION_OPEN = 1,    # OPEN;OPEN;
    EM_CFG_WIRELESS_AUTHENTICATION_SHARED = 2,  # SHARED;SHARED;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA = 3,     # WPA;WPA;
    EM_CFG_WIRELESS_AUTHENTICATION_WPAPSK = 4,  # WPA-PSK;WPA-PSK;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA2 = 5,    # WPA2;WPA2;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA2PSK = 6, # WPA2-PSK;WPA2-PSK;
    EM_CFG_WIRELESS_AUTHENTICATION_WPANONE = 7, # WPA-NONE;WPA-NONE;
    EM_CFG_WIRELESS_AUTHENTICATION_WPAPSK_WPA2PSK = 8,    # WPA-PSK|WPA2-PSK;WPA-PSK/WPA2-PSK;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA_WPA2 = 9,    # WPA|WPA2;WPA/WPA2;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA_WPAPSK = 10,    # WPA | WPA-PSK;WPA/WPA-PSK;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA2_WPA2PSK = 11,    # WPA2|WPA2-PSK;WPA2/WPA2-PSK;
    EM_CFG_WIRELESS_AUTHENTICATION_WPA_WPAPSK_WPA2_WPA2PSK = 12,    # WPA|WPA-PSK|WPA2|WPA2-PSK;WPA/WPA-PSK|WPA2/WPA2-PSK;

class EM_CFG_WIRELESS_DATA_ENCRYPT(IntEnum):
    """
    无线数据加密方式
    DataEncryption type
    """
    EM_CFG_WIRELESS_DATA_ENCRYPT_UNKNOWN = 0,   # UnKnown;UnKnown;
    EM_CFG_WIRELESS_DATA_ENCRYPT_NONE = 1,      # NONE;NONE;
    EM_CFG_WIRELESS_DATA_ENCRYPT_WEP = 2,       # WEP;WEP;
    EM_CFG_WIRELESS_DATA_ENCRYPT_TKIP = 3,      # TKIP;TKIP;
    EM_CFG_WIRELESS_DATA_ENCRYPT_AES = 4,       # AES(CCMP);AES(CCMP);
    EM_CFG_WIRELESS_DATA_ENCRYPT_TKIP_AES = 5,  # TKIP+AES;TKIP+AES;

class EM_CFG_EAP_METHOD(IntEnum):
    """
    EAP方法
    EAP method
    """
    EM_CFG_EAP_METHOD_UNKNOWN = 0,              # UnKnown;UnKnown;
    EM_CFG_EAP_METHOD_PEAP = 1,                 # PEAP;PEAP;
    EM_CFG_EAP_METHOD_TLS = 2,                  # TLS;TLS;
    EM_CFG_EAP_METHOD_TTLS = 3,                 # TTLS;TTLS;

class EM_CFG_EAP_AUTH_TYPE(IntEnum):
    """
    EAP身份验证方法
    EAP AuthType
    """
    EM_CFG_EAP_AUTH_TYPE_UNKNOWN = 0,           # UnKnown;UnKnown;
    EM_CFG_EAP_AUTH_TYPE_NONE = 1,              # NONE;NONE;
    EM_CFG_EAP_AUTH_TYPE_PAP = 2,               # PAP;PAP;
    EM_CFG_EAP_AUTH_TYPE_MSCHAP = 3,            # MSCHAP;MSCHAP;
    EM_CFG_EAP_AUTH_TYPE_MSCHAPV2 = 4,          # MSCHAPV2;MSCHAPV2;
    EM_CFG_EAP_AUTH_TYPE_GTC = 5,               # GTC;GTC;

class EM_CFG_APN(IntEnum):
    """
    接入的网络名称
    the name of the network access
    """
    EM_CFG_APN_CTNET = 0,                       # 中国电信;CTNET;
    EM_CFG_APN_CMNET = 1,                       # 中国移动;CMNET;
    EM_CFG_APN_UNINET = 2,                      # 中国联通;UNINET;

class EM_CFG_DAY3GFLUXTACTIC(IntEnum):
    """
    无线网络连接配置
    每日流量控制策略
    Wireless network configuration
    Daily traffic control strategy
    """
    EM_CFG_DAY3GFLUXTACTIC_BYFLUX = 0,          # 按流量;By traffic;
    EM_CFG_DAY3GFLUXTACTIC_BYTIME = 1,          # 按时间;By time;

class EM_CFG_DAY3GFLUXACTION(IntEnum):
    """
    流量报警策略
    Traffic police tactics
    """
    EM_CFG_DAY3GFLUXACTION_NOTHING = 0,         # 无动作;No Action;
    EM_CFG_DAY3GFLUXACTION_3GNETDOWN = 1,       # 3G下线;3G offline;

class EM_CFG_AUTHMODE(IntEnum):
    """
    鉴权模式
    Authentication mode
    """
    EM_AUTHMODE_NO = 0,                         # 不需要鉴权;Do not need authentication;
    EM_AUTHMODE_PAP = 1,                        # PAP鉴权;PAP authentication;
    EM_AUTHMODE_CHAP = 2,                       # CHAP鉴权;CHAP authentication;

class EM_CFG_3GFLUXTACTIC(IntEnum):
    """
    流量使用策略
    Traffic usage policy
    """
    EM_3GFLUXTACTIC_UNKNOWN = -1,               # 未知类型;unknown;
    EM_3GFLUXTACTIC_BYFLUX = 0,                 # 按月包流量;3G flux tactic by flux;
    EM_3GFLUXTACTIC_BYTIME = 1,                 # 按月包时长;3G flux tactics by time;

class EM_CFG_RAINBRUSHMODE_MODE(IntEnum):
    """
    雨刷工作模式
    RainBrush working mode type
    """
    EM_CFG_RAINBRUSHMODE_MODE_UNKNOWN = 0,      # 未知类型;unknown;
    EM_CFG_RAINBRUSHMODE_MODE_MANUAL = 1,       # 手动模式;manual
    EM_CFG_RAINBRUSHMODE_MODE_TIMING = 2,       # 定时模式;timing;
    EM_CFG_RAINBRUSHMODE_MODE_AUTO = 3,         # 自动感应模式;Auto;
    EM_CFG_RAINBRUSHMODE_MODE_TOUR = 4,         # 雨刷巡航模式;Wiper cruise mode;
    EM_CFG_RAINBRUSHMODE_MODE_CYCLE = 5,        # 周期模式;Cycle

class EM_CFG_RAINBRUSHMODE_MODE(IntEnum):
    """
    雨刷使能电平模式
    RainBrush voltage enable mode type
    """
    EM_CFG_RAINBRUSHMODE_ENABLEMODE_UNKNOWN = 0,    # 未知类型;unknown;
    EM_CFG_RAINBRUSHMODE_ENABLEMODE_LOW = 1,    # 低电平有效（常闭）;low voltage is valid(close always);
    EM_CFG_RAINBRUSHMODE_ENABLEMODE_HIGH = 2,   # 高电平有效（常开）;high voltage is valid(open always);
    EM_CFG_RAINBRUSHMODE_MODE_AUTO = 3,         # 自动感应模式;Auto
    EM_CFG_RAINBRUSHMODE_MODE_TOUR = 4,         # 雨刷巡航模式;Wiper cruise mode
    EM_CFG_RAINBRUSHMODE_MODE_CYCLE = 5,        # 周期模式;Cycle

class EM_CFG_WORKMODE(IntEnum):
    """
    工作模式选择
    working mode selection
    """
    EM_WORKMODE_UNKNOWN = -1,
    EM_WORKMODE_CDMA1X = 0,                     # "CDMA1x";"CDMA1x";
    EM_WORKMODE_EVDO = 1,                       # "EVDO";"EVDO";
    EM_WORKMODE_TDSCDMA = 2,                    # "TD-SCDMA";"TD-SCDMA";
    EM_WORKMODE_WCDMA = 3,                      # "WCDMA";"WCDMA";
    EM_WORKMODE_EDGE = 4,                       # "EDGE";"EDGE";
    EM_WORKMODE_TDDLTE = 5,                     # "TDD-LTE";"TDD-LTE";
    EM_WORKMODE_FDDLTE = 6,                     # "FDD-LTE";"FDD-LTE";
    EM_WORKMODE_TDLTE = 7,                      # "TD-LTE";"TD-LTE";
    EM_WORKMODE_AUTO = 8,                       # "Auto";"Auto";

class EM_A_NET_WIRELESS_DEVICE_TYPE(IntEnum):
    """
    Low Rate Wireless Personal Area Network 低速无线私域网 begin
    /
    无线设备类型
    Low Rate Wireless Personal Area Network low speed wireless private network begin
    Wireless Device Type
    """
    NET_WIRELESS_DEVICE_TYPE_UNKNOWN = 0,
    NET_WIRELESS_DEVICE_TYPE_KEYBOARD = 1,      # 无线键盘;Wireless keyboard;
    NET_WIRELESS_DEVICE_TYPE_DEFENCE = 2,       # 无线防区;Wireless zone;
    NET_WIRELESS_DEVICE_TYPE_REMOTECONTROL = 3, # 无线遥控;Wireless remote control;
    NET_WIRELESS_DEVICE_TYPE_MAGNETOMER = 4,    # 无线门磁;Wireless door sensor;
    NET_WIRELESS_DEVICE_TYPE_ALARMBELL = 5,     # 无线警号;Wireless alarm bell;
    NET_WIRELESS_DEVICE_TYPE_SWITCHER = 6,      # 无线插座;Wireless switcher;
    NET_WIRELESS_DEVICE_TYPE_SMARTLOCK = 7,     # 无线智能锁;Wireless smart lock;
    NET_WIRELESS_DEVICE_TYPE_REPEATER = 8,      # 无线中继器;Wireless Repeater;

class EM_WIRELESS_DEVICE_MODE(IntEnum):
    """
    无线设备工作模式
    Wireless Device Mode
    """
    EM_WIRELESS_DEVICE_MODE_UNKNOWN = 0,        # 模式未识别;
    EM_WIRELESS_DEVICE_MODE_NORMAL = 1,         # Normal 普通模式;Normal;
    EM_WIRELESS_DEVICE_MODE_POLLING = 2,        # Polling 巡检模式 只有Type为RemoteControl时才能处于巡检模式;Polling It only to be valid when emType is NET_WIRELESS_DEVICE_TYPE_REMOTECONTROL;

class EM_CODEID_SENSE_METHOD_TYPE(IntEnum):
    """
    传感器方式
    the type of sense method
    """
    EM_CODEID_SENSE_METHOD_TYPE_UNKOWN = 0,     # 未知的;Unknown;
    EM_CODEID_SENSE_METHOD_TYPE_DOOR_MAGNETISM = 1,    # 门磁;Door Magnetism;
    EM_CODEID_SENSE_METHOD_TYPE_GAS_SENSOR = 2, # 燃气传感;Gas Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_CURTAIN_SENSOR = 3,    # 幕帘传感器;Curtain Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_MOBILE_SENSOR = 4,    # 移动传感器;Mobile Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_PASSIVEINFRA = 5,    # 被动红外传感器;Passive Infrared Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_URGENCY_BUTTON = 6,    # 紧急按钮;Urgency Button;
    EM_CODEID_SENSE_METHOD_TYPE_SMOKING_SENSOR = 7,    # 烟雾传感器;Smoking Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_DOUBLEMETHOD = 8,    # 双鉴传感器(红外+微波);DoubleMethod(Infrare+Microwave);
    EM_CODEID_SENSE_METHOD_TYPE_WATER_SENSOR = 9,    # 水浸传感器;Water Sensor;
    EM_CODEID_SENSE_METHOD_TYPE_THREEMETHOD = 10,    # 三技术;Three Sensor;

class EM_A_NET_CODEID_ERROR_TYPE(IntEnum):
    """
    对码错误类型
    Code error type
    """
    NET_CODEID_ERROR_TYPE_RIGHT = 0,            # 对码正确;Code correct;
    NET_CODEID_ERROR_TYPE_ALREADYEXIST = 1,     # 已经存在;Exists;
    NET_CODEID_ERROR_TYPE_OTHER = 2,            # 其他错误;Other error;

class EM_GETUSERINFOBYCONDITION_USER_STATUS(IntEnum):
    """
    用户状态
    user status
    """
    EM_GETUSERINFOBYCONDITION_USER_STATUS_UNKNOWN = 0,    # 未知;unknown;
    EM_GETUSERINFOBYCONDITION_USER_STATUS_NOPRESENT = 1,    # 不存在，未配置过用户信息;does not exist, user information has not been configured;
    EM_GETUSERINFOBYCONDITION_USER_STATUS_INACTIVATED = 2,    # 未激活，已经配置过用户信息，但是未使能;not activated, user information has been configured, but not enabled;
    EM_GETUSERINFOBYCONDITION_USER_STATUS_ACTIVATED = 3,    # 已激活;activated;

class EM_ALARM_USERAUTHORITY(IntEnum):
    """
    用户的权限列表
    User's permission list
    """
    EM_ALARM_USERAUTHORITY_UNKNOWN = 0,         # 未知;unknown;
    EM_ALARM_USERAUTHORITY_ARMING = 1,          # 布防;Arming;
    EM_ALARM_USERAUTHORITY_FORCEARMING = 2,     # 强制布防;force arming;
    EM_ALARM_USERAUTHORITY_DISARM = 3,          # 撤防;Disarm;
    EM_ALARM_USERAUTHORITY_BYPASS = 4,          # 旁路;Bypass;
    EM_ALARM_USERAUTHORITY_PERMANENTBYPASS = 5, # 永久旁路;permanent bypass;
    EM_ALARM_USERAUTHORITY_ALARMCONFIRM = 6,    # 消警;Alarm elimination;
    EM_ALARM_USERAUTHORITY_QUERYLOG = 7,        # 查询日志;query log;
    EM_ALARM_USERAUTHORITY_DEBUGMODE = 8,       # 调试模式;debug mode;
    EM_ALARM_USERAUTHORITY_UPGRADE = 9,         # 更改基本程序，如：升级程序;Change the basic program, such as: upgrade program;
    EM_ALARM_USERAUTHORITY_SYSTEMCONFIG = 10,   # 添加/更改配置参数;add/change configuration parameters;
    EM_ALARM_USERAUTHORITY_USERMANAGEMENT = 11, # 用户管理;user management;

class EM_ALARM_USER_GROUP(IntEnum):
    """
    用户所在组
    User's group
    """
    EM_ALARM_USER_GROUP_UNKNOWN = 0,            # 未知;unknown;
    EM_ALARM_USER_GROUP_ADMIN = 1,              # 管理员;Administrator;
    EM_ALARM_USER_GROUP_INSTALLER = 2,          # 安装员;installer;
    EM_ALARM_USER_GROUP_MANUFACTURER = 3,       # 制造商;manufacturer;
    EM_ALARM_USER_GROUP_OPERATOR = 4,           # 操作员;operator;

class EM_GETUSERINFOBYCONDITION_USER_TYPE(IntEnum):
    """
    码流类型
    stream type
    """
    EM_GETUSERINFOBYCONDITION_USER_TYPE_UNKNOWN = 0,    # 未知;unknown;
    EM_GETUSERINFOBYCONDITION_USER_TYPE_KEYPAD = 1,    # 键盘用户;keyboard user;
    EM_GETUSERINFOBYCONDITION_USER_TYPE_ICCARD = 2,    # IC卡用户;IC card user;
    EM_GETUSERINFOBYCONDITION_USER_TYPE_REMOTECONTROL = 3,    # 遥控器用户;remote control user;
    EM_GETUSERINFOBYCONDITION_USER_TYPE_MOBILE = 4,    # 手机用户;mobile phone users;
    EM_GETUSERINFOBYCONDITION_USER_TYPE_KEY = 5,    # key用户;key user;

class EM_ALARM_ONECLICKARMING_FUNCTION(IntEnum):
    """
    功能
    Features
    """
    EM_ALARM_ONECLICKARMING_FUNCTION_UNKNOWN = 0,    # 未知;unknown;
    EM_ALARM_ONECLICKARMING_FUNCTION_ONOFF = 1, # 开关;switch;
    EM_ALARM_ONECLICKARMING_FUNCTION_ONONLY = 2,    # 只开;only open;
    EM_ALARM_ONECLICKARMING_FUNCTION_OFFONLY = 3,    # 只关;only off;

class EM_ALARM_ONECLICKARMING_TRIGGEROPTION(IntEnum):
    """
    触发类型
    trigger type
    """
    EM_ALARM_ONECLICKARMING_TRIGGEROPTION_UNKNOWN = 0,    # 未知;unknown;
    EM_ALARM_ONECLICKARMING_TRIGGEROPTION_IMPULSE = 1,    # 脉冲;impulse;
    EM_ALARM_ONECLICKARMING_TRIGGEROPTION_BISTABLE = 2,    # 双稳定;Bistable;

class EM_CLASSROOM_ACTION(IntEnum):
    """
    课堂行为动作类型
    classroom action type
    """
    EM_CLASSROOM_ACTION_UNKNOWN = 0,            # 未知;unknown;
    EM_CLASSROOM_ACTION_PLAY_PHONE = 1,         # 玩手机;play phone;
    EM_CLASSROOM_ACTION_HANDSUP = 2,            # 举手;hands up;
    EM_CLASSROOM_ACTION_LISTEN = 3,             # 听讲;listen;
    EM_CLASSROOM_ACTION_READ_WRITE = 4,         # 读写;read and write;
    EM_CLASSROOM_ACTION_TABLE = 5,              # 趴桌子;on table;
    EM_CLASSROOM_ACTION_TURN = 6,               # 转身;turn;

class EM_USERMANAGER_IMAGE_TYPE(IntEnum):
    """
    图片类型
    image type
    """
    EM_USERMANAGER_IMAGE_TYPE_UNKNOWN = -1,     # 未知;unknown;
    EM_USERMANAGER_IMAGE_TYPE_LOCAL = 0,        # 本地目标库图;local image;
    EM_USERMANAGER_IMAGE_TYPE_SCENE = 1,        # 拍摄场景图;scene image;
    EM_USERMANAGER_IMAGE_TYPE_FACE = 2,         # 目标抠图;target image;
    EM_USERMANAGER_IMAGE_TYPE_INFRARED = 3,     # 红外抓图;infra-red image;
    EM_USERMANAGER_IMAGE_TYPE_ENTOURAGE = 4,    # 陪同人员抓图;Entourage image;
    EM_USERMANAGER_IMAGE_TYPE_THERMOGRAM = 5,   # 热图;Thermogram image;

class EM_A_NET_ACCESS_CTL_EVENT_TYPE(IntEnum):
    """
    门禁事件类型
    Entrance Guard Event Type
    """
    NET_ACCESS_CTL_EVENT_UNKNOWN = 0,
    NET_ACCESS_CTL_EVENT_ENTRY = 1,             # 进门;Get In;
    NET_ACCESS_CTL_EVENT_EXIT = 2,              # 出门;Get Out;

class EM_A_NET_ACCESSCTLCARD_TYPE(IntEnum):
    """
    卡类型
    Card Type
    """
    NET_ACCESSCTLCARD_TYPE_UNKNOWN = -1,
    NET_ACCESSCTLCARD_TYPE_GENERAL = 0,         # 一般卡;General Card;
    NET_ACCESSCTLCARD_TYPE_VIP = 1,             # VIP卡;VIP Card;
    NET_ACCESSCTLCARD_TYPE_GUEST = 2,           # 来宾卡;Guest Card;
    NET_ACCESSCTLCARD_TYPE_PATROL = 3,          # 巡逻卡;Patrol Card;
    NET_ACCESSCTLCARD_TYPE_BLACKLIST = 4,       # 禁止名单卡;Blocklist Card;
    NET_ACCESSCTLCARD_TYPE_CORCE = 5,           # 胁迫卡;Corce Card;
    NET_ACCESSCTLCARD_TYPE_POLLING = 6,         # 巡检卡;Polling Card;
    NET_ACCESSCTLCARD_TYPE_GB_CUSTOM1 = 7,      # 国标自定义1卡,不支持配套;Custom card 1;
    NET_ACCESSCTLCARD_TYPE_GB_CUSTOM2 = 8,      # 国标自定义2卡,不支持配套;Custom card 2;
    NET_ACCESSCTLCARD_TYPE_TEMPORARY_PERSON = 9,    # 临时人员，不支持配套;temporary person;
    NET_ACCESSCTLCARD_TYPE_INVENTORY_PERSON = 10,    # 清分人员，不支持配套;inventory person;
    NET_ACCESSCTLCARD_TYPE_INVENTORY_DIRECTOR = 11,    # 清分主管，不支持配套;inventory director;
    NET_ACCESSCTLCARD_TYPE_SECURITY_GUARD = 12, # 保卫人员，不支持配套;security guard;
    NET_ACCESSCTLCARD_TYPE_SECURITYGUARD_DIRECTOR = 13,    # 保卫主管，不支持配套;security guard director;
    NET_ACCESSCTLCARD_TYPE_STORE_KEEPER = 14,   # 库管员，不支持配套;store keeper;
    NET_ACCESSCTLCARD_TYPE_STORE_DIRECTOR = 15, # 库主管，不支持配套;store director;
    NET_ACCESSCTLCARD_TYPE_ESCORT_PERSON = 16,  # 押运人员，不支持配套;escort person;
    NET_ACCESSCTLCARD_TYPE_REPAIR_PERSON = 17,  # 维修人员，不支持配套;repair person;
    NET_ACCESSCTLCARD_TYPE_INSPECTOR = 18,      # 检查人员，不支持配套;inspector;
    NET_ACCESSCTLCARD_TYPE_SHENZHENLINK = 19,   # 不支持配套;does not support matching;
    NET_ACCESSCTLCARD_TYPE_MOTHERCARD = 255,    # 母卡;Mother Card;

class EM_A_NET_ACCESS_DOOROPEN_METHOD(IntEnum):
    """
    开门方式(门禁事件,门禁出入记录,实际的开门方式)
    Door Open Method(Entrance Guard Event,Entrance Guard get In/Out Record, Actual Open Door Method)
    """
    NET_ACCESS_DOOROPEN_METHOD_UNKNOWN = 0,
    NET_ACCESS_DOOROPEN_METHOD_PWD_ONLY = 1,    # 密码开锁;Password;
    NET_ACCESS_DOOROPEN_METHOD_CARD = 2,        # 刷卡开锁;Card;
    NET_ACCESS_DOOROPEN_METHOD_CARD_FIRST = 3,  # 先刷卡后密码开锁;First Card Then Password;
    NET_ACCESS_DOOROPEN_METHOD_PWD_FIRST = 4,   # 先密码后刷卡开锁;First Password Then Card;
    NET_ACCESS_DOOROPEN_METHOD_REMOTE = 5,      # 远程开锁,如通过室内机或者平台对门口机开锁;Long-Range Open,Such as Through theIndoor Unit or Unlock the Door Machine Platform;
    NET_ACCESS_DOOROPEN_METHOD_BUTTON = 6,      # 开锁按钮进行开锁;Open Door Button;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT = 7, # 信息开锁;information lock;
    NET_ACCESS_DOOROPEN_METHOD_PWD_CARD_FINGERPRINT = 8,    # 密码+刷卡+信息组合开锁;password+swipe card+information combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_PWD_FINGERPRINT = 10,    # 密码+信息组合开锁;password+information combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_FINGERPRINT = 11,    # 刷卡+信息组合开锁;swipe card+information combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_PERSONS = 12,    # 多人开锁;multi-people unlock;
    NET_ACCESS_DOOROPEN_METHOD_KEY = 13,        # 钥匙开门;Key;
    NET_ACCESS_DOOROPEN_METHOD_COERCE_PWD = 14, # 胁迫密码开门;Use force password to open the door;
    NET_ACCESS_DOOROPEN_METHOD_QRCODE = 15,     # 二维码开门;Use QR Code;
    NET_ACCESS_DOOROPEN_METHOD_FACE_RECOGNITION = 16,    # 目标识别开门;target recogniton to open the door;
    NET_ACCESS_DOOROPEN_METHOD_FACEIDCARD = 18, # 人证对比;comparsion of target and ID card;
    NET_ACCESS_DOOROPEN_METHOD_FACEIDCARD_AND_IDCARD = 19,    # 证件+ 人证比对;ID card and compasion of target and ID card;
    NET_ACCESS_DOOROPEN_METHOD_BLUETOOTH = 20,  # 蓝牙开门;Bluetooth;
    NET_ACCESS_DOOROPEN_METHOD_CUSTOM_PASSWORD = 21,    # 个性化密码开门;Custom password;
    NET_ACCESS_DOOROPEN_METHOD_USERID_AND_PWD = 22,    # UserID+密码;UserID and password;
    NET_ACCESS_DOOROPEN_METHOD_FACE_AND_PWD = 23,    # 目标+密码开锁;target and password;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_AND_PWD = 24,    # 信息+密码开锁;information and password;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_AND_FACE = 25,    # 信息+目标开锁;information and target;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FACE = 26,    # 刷卡+目标开锁;Card and target;
    NET_ACCESS_DOOROPEN_METHOD_FACE_OR_PWD = 27,    # 目标或密码开锁;target or password;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_OR_PWD = 28,    # 信息或密码开锁;information or password;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_OR_FACE = 29,    # 信息或开锁;information or target;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FACE = 30,    # 刷卡或目标开锁;Card or target;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FINGERPRINT = 31,    # 刷卡或信息开锁;Card or information;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_AND_FACE_AND_PWD = 32,    # 信息+目标+密码开锁;information and target and password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FACE_AND_PWD = 33,    # 刷卡+目标+密码开锁;Card and target and password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FINGERPRINT_AND_PWD = 34,    # 刷卡+信息+密码开锁;Card and information and password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_PWD_AND_FACE = 35,    # 卡+信息+目标组合开锁;Card and password and target;
    NET_ACCESS_DOOROPEN_METHOD_FINGERPRINT_OR_FACE_OR_PWD = 36,    # 信息或目标或密码;information or target or password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FACE_OR_PWD = 37,    # 卡或目标或密码开锁;Card or target or password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FINGERPRINT_OR_FACE = 38,    # 卡或信息或目标开锁;Card or information or target;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FINGERPRINT_AND_FACE_AND_PWD = 39,    # 卡+信息+目标+密码组合开锁;Card and information and target and password;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FINGERPRINT_OR_FACE_OR_PWD = 40,    # 卡或信息或目标或密码开锁;Card or information or target or password;
    NET_ACCESS_DOOROPEN_METHOD_FACEIPCARDANDIDCARD_OR_CARD_OR_FACE = 41,    # (证件+人证比对)或 刷卡 或 目标;ID card and compasion of target and ID card or card or target;
    NET_ACCESS_DOOROPEN_METHOD_FACEIDCARD_OR_CARD_OR_FACE = 42,    # 人证比对 或 刷卡(二维码) 或 目标;ID card and compasion of target or card or target;
    NET_ACCESS_DOOROPEN_METHOD_DTMF = 43,       # DTMF开锁(包括SIPINFO,RFC2833,INBAND);DTMF unlock(include SIPINFO,RFC2833,INBAND);
    NET_ACCESS_DOOROPEN_METHOD_REMOTE_QRCODE = 44,    # 远程二维码开门;remote QR code to open the door;
    NET_ACCESS_DOOROPEN_METHOD_REMOTE_FACE = 45,    # 远程目标开门;remote target to open the door;
    NET_ACCESS_DOOROPEN_METHOD_CITIZEN_FINGERPRINT = 46,    # 人证比对开门(信息);card picture(fingerprint);
    NET_ACCESS_DOOROPEN_METHOD_TEMPORARY_PASSWORD = 47,    # 临时密码开门;Temporary password;
    NET_ACCESS_DOOROPEN_METHOD_HEALTHCODE = 48, # 健康码开门;Health code;
    NET_ACCESS_DOOROPEN_METHOD_IRIS = 49,       # 目标识别开锁;iris recognition unlock;
    NET_ACCESS_DOOROPEN_METHOD_IRIS_AND_PASSWORD = 50,    # 眼睛+密码组合开锁;iris + password combination to unlock;
    NET_ACCESS_DOOROPEN_METHOD_FACE_AND_IRIS = 51,    # 目标+眼睛组合开锁;target + iris combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_IRIS = 52,    # 卡+眼睛组合开锁;Card + iris combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_IRIS_OR_PASSWORD = 53,    # 眼睛或密码开锁;iris or password unlock;
    NET_ACCESS_DOOROPEN_METHOD_FACE_OR_IRIS = 54,    # 目标或眼睛开锁;target or iris unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_IRIS = 55,    # 卡或眼睛开锁;Card or iris unlock;
    NET_ACCESS_DOOROPEN_METHOD_FACE_AND_IRIS_AND_PASSWORD = 56,    # 目标+眼睛+密码组合开锁;target + iris + password combination to unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FACE_AND_IRIS = 57,    # 卡+目标+眼睛组合开锁;Card + target + iris combination unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_IRIS_AND_PASSWORD = 58,    # 卡+眼睛+密码组合开锁;Card + iris + password combination to unlock;
    NET_ACCESS_DOOROPEN_METHOD_FACE_OR_IRIS_OR_PASSWORD = 59,    # 目标或眼睛或密码开锁;target or iris or password unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FACE_OR_IRIS = 60,    # 卡或目标或眼睛开锁;Card or target or iris unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_IRIS_OR_PASSWORD = 61,    # 卡或眼睛或密码开锁;Card or iris or password unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_AND_FACE_AND_IRIS_AND_PASSWORD = 62,    # 卡+目标+眼睛+密码组合开锁;Card + target + iris + password combination to unlock;
    NET_ACCESS_DOOROPEN_METHOD_CARD_OR_FACE_OR_IRIS_OR_PASSWORD = 63,    # 卡或目标或眼睛或密码开锁;Card or target or iris or password to unlock;

class EM_A_NET_ATTENDANCESTATE(IntEnum):
    """
    考勤状态
    attendance state
    """
    NET_ATTENDANCESTATE_UNKNOWN = 0,
    NET_ATTENDANCESTATE_SIGNIN = 1,             # 签入;
    NET_ATTENDANCESTATE_GOOUT = 2,              # 外出;
    NET_ATTENDANCESTATE_GOOUT_AND_RETRUN = 3,   # 外出归来;
    NET_ATTENDANCESTATE_SIGNOUT = 4,            # 签出;
    NET_ATTENDANCESTATE_WORK_OVERTIME_SIGNIN = 5,    # 加班签到;
    NET_ATTENDANCESTATE_WORK_OVERTIME_SIGNOUT = 6,    # 加班签出;

class EM_A_NET_ACCESSCTLCARD_SEX(IntEnum):
    """
    性别
    sex
    """
    NET_ACCESSCTLCARD_SEX_UNKNOWN = 0,
    NET_ACCESSCTLCARD_SEX_MALE = 1,             # 男;male;
    NET_ACCESSCTLCARD_SEX_FEMALE = 2,           # 女;female;

class EM_PROTOCOL_NAME(IntEnum):
    """
    协议名称
    Protocol name
    """
    EM_PROTOCOL_NAME_UNKNOWN = 0,               # 未知;Unknown;
    EM_PROTOCOL_NAME_GB28181 = 1,               # Gb28181;Gb28181;
    EM_PROTOCOL_NAME_MAX = 2,                   # 最大值;Max;

class EM_PERIPHERAL_TYPE(IntEnum):
    """
    外设类型
    Peripheral type
    """
    EM_PERIPHERAL_NUKNOWN = 0,                  # 未知;Unknown;
    EM_PERIPHERAL_ASG_CONTROLLER = 1,           # 闸机控制板;AsgController;
    EM_PERIPHERAL_ASG_MOTOR = 2,                # 闸机电机驱动;AsgMotor;
    EM_PERIPHERAL_SECURITYGATE_DOOR_CONTROLLER = 3,    # 安检门门板控制器;Security gate door controller;
    EM_PERIPHERAL_INFRARED_TEMPERATURE_UNIT = 4,    # 红外测温模块;Infrared temperature unit;
    EM_PERIPHERAL_ASG_VOICE = 5,                # 闸机语音模块;Asg voice;
    EM_PERIPHERAL_ASG_READER = 6,               # 闸机读卡器;Asg reader;
    EM_PERIPHERAL_RTSCCOMMBOARD = 7,            # 信号机通讯板;Rtsc Comm Board;
    EM_PERIPHERAL_SINGLECHIPMICROCOMPUTER = 8,  # 单片机;Single Chip Microcomputer;
    EM_PERIPHERAL_RECLOSING = 9,                # 重合闸;reclosing;
    EM_PERIPHERAL_AIRSWITCHVERSION = 10,        # 空开;air Switch Version;
    EM_PERIPHERAL_COS = 11,                     # 国密芯片COS版本;COS;

class EM_SMOKE_COLOR(IntEnum):
    """
    烟雾颜色类型
    smoke color type
    """
    EM_SMOKE_COLOR_UNKNOWN = 0,                 # 未知;unknown;
    EM_SMOKE_COLOR_WHITE = 1,                   # White;White;
    EM_SMOKE_COLOR_BLACK = 2,                   # black;black;
    EM_SMOKE_COLOR_RED = 3,                     # red;red;
    EM_SMOKE_COLOR_YELLOW = 4,                  # yellow;yellow;

class EM_A_NET_ACCESS_CTL_STATUS_TYPE(IntEnum):
    """
    门禁状态类型
    Access Control Status Type
    """
    NET_ACCESS_CTL_STATUS_TYPE_UNKNOWN = 0,
    NET_ACCESS_CTL_STATUS_TYPE_OPEN = 1,        # 开门;Open;
    NET_ACCESS_CTL_STATUS_TYPE_CLOSE = 2,       # 关门;Close;
    NET_ACCESS_CTL_STATUS_TYPE_ABNORMAL = 3,    # 异常;Abnormal;
    NET_ACCESS_CTL_STATUS_TYPE_FAKELOCKED = 4,  # 假锁;fake locked;
    NET_ACCESS_CTL_STATUS_TYPE_CLOSEALWAYS = 5, # 常闭;close always;
    NET_ACCESS_CTL_STATUS_TYPE_OPENALWAYS = 6,  # 常开;open always;
    NET_ACCESS_CTL_STATUS_TYPE_NORMAL = 7,      # 正常;Normal;

class EM_WORK_HELMET_STATE(IntEnum):
    """
    安全帽佩戴状态
    The state of helmet
    """
    EM_HELMET_STATE_UNKNOWN = 0,                # 未知;Unknown;
    EM_HELMET_STATE_NOTWEAR = 1,                # 不带安全帽;No helmet;
    EM_HELMET_STATE_WEAR = 2,                   # 有带安全帽;Wear helmet;
    EM_HELMET_STATE_INCONFORMITY_COLOR = 3,     # 不存在指定颜色的安全帽;There is no helmet of the specified color;

class EM_WORKCLOTHES_STATE(IntEnum):
    """
    工作服穿戴状态
    The state of work clothes
    """
    EM_WORKCLOTHES_STATE_UNKNOWN = 0,           # 未知;Unknown;
    EM_WORKCLOTHES_STATE_NOTWEAR = 1,           # 无工作服;No work clothes;
    EM_WORKCLOTHES_STATE_WEAR = 2,              # 有工作服;Wear work clothes;

class EM_CLOTHES_LEGAL_STATE(IntEnum):
    """
    工作服合法状态
    Legal status of work clothes
    """
    EM_CLOTHES_LEGAL_STATE_UNKNOWN = 0,         # 未知;Unknown;
    EM_CLOTHES_LEGAL_STATE_WRONGFUL = 1,        # 不合法;Wrongful;
    EM_CLOTHES_LEGAL_STATE_LEGAL = 2,           # 合法;Legal;

class EM_WORKPANTS_STATE(IntEnum):
    """
    工作裤穿戴状态
    Work pants state
    """
    EM_WORKPANTS_STATE_UNKNOWN = 0,             # 未知;unknown;
    EM_WORKPANTS_STATE_NOTWEAR = 1,             # 没有;not wear;
    EM_WORKPANTS_STATE_WEAR = 2,                # 有;wear;

class EM_EVENT_WORKCLOTHES_RULE_TYPE(IntEnum):
    """
    工装检测报警规则类型
    Rule type of work clothes(helmet/clothes)detection
    """
    EM_EVENT_WORKCLOTHES_RULE_UNKNWON = 0,      # 未知;Unknown;
    EM_EVENT_WORKCLOTHES_RULE_HELMET = 1,       # 安全帽;Helmet;
    EM_EVENT_WORKCLOTHES_RULE_CLOTHES = 2,      # 工作服;Clothes;
    EM_EVENT_WORKCLOTHES_RULE_PANTS = 3,        # 工作裤;Pant;
    EM_EVENT_WORKCLOTHES_RULE_PROTECTIVESUIT = 4,    # 防护服;ProtectiveSuit;
    EM_EVENT_WORKCLOTHES_RULE_SHOESCOVER = 5,   # 鞋套;ShoesCover;
    EM_EVENT_WORKCLOTHES_RULE_SAFETYROPE = 6,   # 安全绳;SafetyRope;
    EM_EVENT_WORKCLOTHES_RULE_NORMALHAT = 7,    # 普通帽;NormalHat;
    EM_EVENT_WORKCLOTHES_RULE_MASK = 8,         # 口罩;Mask;
    EM_EVENT_WORKCLOTHES_RULE_APRON = 9,        # 围裙;Apron;
    EM_EVENT_WORKCLOTHES_RULE_GLOVE = 10,       # 手套;Glove;
    EM_EVENT_WORKCLOTHES_RULE_BOOT = 11,        # 靴子;Boot;
    EM_EVENT_WORKCLOTHES_RULE_NOHAT = 12,       # 无帽子;NoHat;
    EM_EVENT_WORKCLOTHES_RULE_TYPE_PROHLMET = 13,    # 防护面罩;Protective mask;
    EM_EVENT_WORKCLOTHES_RULE_FIREPROOFCLOTHES = 14,    # 防火衣;FireProofClothes;
    EM_EVENT_WORKCLOTHES_RULE_UNIFORM = 15,     # 制服;Uniform;
    EM_EVENT_WORKCLOTHES_RULE_MULTIMETER = 16,  # 万用表;Multimeter;
    EM_EVENT_WORKCLOTHES_RULE_BREATHINGMASK = 17,    # 呼吸面罩检测;BreathingMask;
    EM_EVENT_WORKCLOTHES_RULE_GLASSES = 18,     # 眼镜;Glasses;
    EM_EVENT_WORKCLOTHES_RULE_VEST = 19,        # 反光衣;Vest;
    EM_EVENT_WORKCLOTHES_RULE_WRISTGUARD = 20,  # 防割护腕;WristGuard;
    EM_EVENT_WORKCLOTHES_RULE_SAFETYSHOES = 21, # 劳保鞋;SafetyShoes;
    EM_EVENT_WORKCLOTHES_RULE_HOOD = 22,        # 头套;hood;

class EM_WEARING_STATE(IntEnum):
    """
    穿戴状态
    Wear state
    """
    EM_WEARING_STATE_UNKNOWN = 0,               # 未知;unknown;
    EM_WEARING_STATE_NOTWEAR = 1,               # 没有穿戴;not wearing;
    EM_WEARING_STATE_WEAR = 2,                  # 有穿戴;Wear;
    EM_WEARING_STATE_NO_EXIT = 3,               # 不存在指定颜色的帽子;There is no hat of the specified color;

class EM_COMPLIANCE_STATE(IntEnum):
    """
    合规检测状态
    Compliance detection status
    """
    EM_COMPLIANCE_STATE_COMPLIANT = 0,          # 合规;Compliant;
    EM_COMPLIANCE_STATE_NONCOMPLIANT = 1,       # 不合规;not compliant;
    EM_COMPLIANCE_STATE_UNKNOWN = 2,            # 未知;unknown;

class EM_FIREPROOF_CLOTHES_STATE(IntEnum):
    """
    是否穿着防火衣
    FireProofClothes state
    """
    EM_FIREPROOF_CLOTHES_STATE_UNKNOWN = 0,     # 未知;unknown;
    EM_FIREPROOF_CLOTHES_STATE_NO = 1,          # 没有穿着防火衣;not FireProofClothes;
    EM_FIREPROOF_CLOTHES_STATE_YES = 2,         # 有穿着防火衣;FireProofClothes;
    EM_FIREPROOF_CLOTHES_STATE_NOEXIT = 3,      # 不存在指定颜色的防火衣;There is no hat of the specified color;

class EM_GLASSES_RULE_TYPE(IntEnum):
    """
    眼镜检测规则中报警类型
    glasses detection rule alarm type
    """
    EM_GLASSES_RULE_TYPE_UNKNOWN = -1,          # 未知;the unknown;
    EM_GLASSES_RULE_TYPE_NO_GLASSES = 0,        # 无眼镜;No glasses;
    EM_GLASSES_RULE_TYPE_SUN_GLASSES = 1,       # 太阳镜;sunglasses;
    EM_GLASSES_RULE_TYPE_BLACK_RIMMED_GLASSES = 2,    # 黑框眼镜;black-rimmed glasses;
    EM_GLASSES_RULE_TYPE_HALF_RIMMED_GLASSES = 3,    # 半框眼镜;half-rimmed glasses;
    EM_GLASSES_RULE_TYPE_RIMLESS_GLASSES = 4,   # 无框眼镜;his rimless glasses;
    EM_GLASSES_RULE_TYPE_NORMAL_GLASSES = 5,    # 普通眼镜;ordinary glasses;
    EM_GLASSES_RULE_TYPE_INDUSTRIAL_SAFETY_GLASSES = 6,    # 工业护目镜;Industrial goggles;

class EM_ACTION(IntEnum):
    """
    物体动作支持类型
    Object action support type
    """
    EM_ACTION_UNKNOWN = 0,                      # 未知类型;Unknown type;
    EM_ACTION_APPEAR = 1,                       # 第一次出现在检测区域中，或者跟踪时物理分离动作中尚未确认的新物体;Appears in the detection area for the first time, or a new object that has not been confirmed in the physical separation action during tracking;
    EM_ACTION_MOVE = 2,                         # 正在运动，物体被正常跟踪;Moving, the object is being tracked normally;
    EM_ACTION_STAY = 3,                         # 物体停止运动，这个物体不会在出现在下一帧物体列表中，物体开始移动后再恢复在列表中;The object stops moving, this object will not appear in the object list in the next frame, and the object will resume in the list after it starts to move;
    EM_ACTION_REMOVE = 4,                       # 物体从原来的区域移除，或者被遮盖，或者跟踪失败，移除的物体ID不会被自动删除，并且物体重现出现是有可能再次被使用;If the object is removed from the original area, or is covered, or the tracking fails, the ID of the removed object will not be automatically deleted, and the object may be used again if it reappears;
    EM_ACTION_DISAPPEAR = 5,                    # 运动到跟踪区域之外，或者达到了算法跟踪物体的上限而被清除，消失的物体ID将不再出现;Move out of the tracking area, or reach the upper limit of the algorithm to track the object and be cleared, the disappeared object ID will no longer appear;
    EM_ACTION_SPLIT = 6,                        # 从其他物体中分离出来，可以用来检测物体遗留，关联ID表示从这个ID对应物体分离;Separated from other objects, it can be used to detect objects left behind, and the associated ID means separation from the corresponding object of this ID;
    EM_ACTION_MERGE = 7,                        # 合并到其他物体，可以用来检查物体保全，关联ID表示合并到这个ID对相应的物体;Merge to other objects, can be used to check the preservation of the object, the associated ID means that the ID is merged to the corresponding object;
    EM_ACTION_RENAME = 8,                       # 如果算法无法确定分离动作中某个物体是原先同一个物体，应该创建先一个新的物体，证据充分后再重命名为旧的物体ID，关联ID表示暂时使用的新的ID。;If the algorithm cannot determine that an object in the separation action is the same object originally, a new object should be created first, and then renamed to the old object ID after sufficient evidence. The associated ID represents the new ID that is temporarily used.;

class EM_BOAT_DIRECTION(IntEnum):
    """
    船只行驶方向
    The direction of the boat
    """
    EM_BOAT_DIRECTION_UNKNOWN = 0,              # 未知;Unknown;
    EM_BOAT_DIRECTION_OPPOSITE = 1,             # 逆向;Opposite direction;
    EM_BOAT_DIRECTION_POSITIVE = 2,             # 正向;Positive direction;

class EM_NUMBER_STAT_TYPE(IntEnum):
    """
    表示人数越上限类型
    Indicates that the number of people exceeds the upper limit
    """
    EM_NUMBERSTAT_TYPE_UNKNOWN = 0,             # 未知;Unknown;
    EM_NUMBERSTAT_TYPE_ENTEROVER = 1,           # 进入;Enter over;
    EM_NUMBERSTAT_TYPE_EXITOVER = 2,            # 退出;Exit over;
    EM_NUMBERSTAT_TYPE_INSIDEOVER = 3,          # 在里面;Inside over;
    EM_NUMBERSTAT_TYPE_PASSOVER = 4,            # 经过;Pass over;

class EM_EVENT_DETECT_TYPE(IntEnum):
    """
    检测模式
    Detection mode
    """
    EM_EVENT_DETECT_TYPE_UNKNOWN = -1,          # 未知;unknown;
    EM_EVENT_DETECT_TYPE_LESS_OR_EQUAL = 0,     # 小于等于阈值报警;Less than or equal to the threshold alarm;
    EM_EVENT_DETECT_TYPE_GREATER_OR_EQUAL = 1,  # 大于等于阈值报警;greater than or equal to the threshold alarm;
    EM_EVENT_DETECT_TYPE_EQUAL = 2,             # 等于阀值报警;equal to threshold alarm;
    EM_EVENT_DETECT_TYPE_NOEQUAL = 3,           # 不等于阀值报警;Not equal to threshold alarm;
    EM_EVENT_DETECT_TYPE_CHANGE = 4,            # 人数变化报警;Alarm for changes in the number of people;
    EM_EVENT_DETECT_TYPE_GREATER = 5,           # 大于阈值报警;greater than the threshold alarm;
    EM_EVENT_DETECT_TYPE_LESS = 6,              # 小于阈值报警;less than threshold alarm;
    EM_EVENT_DETECT_TYPE_IN_INTERVAL = 7,       # 区间内报警，检测人数在区间范围内报警，包括边界值。区间值对应PersonNum字段;Alarm in the interval, the number of people detected in the interval is alarmed, including the boundary value.;
    EM_EVENT_DETECT_TYPE_OUT_INTERVAL = 8,      # 区间外报警，检测人数在区间范围外报警，不包括边界值。区间值对应PersonNum字段;Alarm outside the interval, alarm when the number of people detected is outside the interval, excluding the boundary value.;

class EM_COMPARE_RESULT(IntEnum):
    """
    比对结果
    compare result
    """
    EM_COMPARE_RESULT_UNKNOWN = -1,             # 未知;unknown;
    EM_COMPARE_RESULT_SUCCESS = 0,              # 成功;success;
    EM_COMPARE_RESULT_OTHERERROR = 1,           # 其他错误;other error;
    EM_COMPARE_RESULT_NOTINDATABASE = 2,        # 不在目标库中;not in target database;
    EM_COMPARE_RESULT_EXCEED_SINGLE_DAY_ENTER_TIMES = 3,    # 超过单日进门次数限制;exceed enter times in single day;
    EM_COMPARE_RESULT_NO_ENTER_RECORD_LEAVE_FAIL = 4,    # 无进门记录，离开失败;no enter record, leave fail;
    EM_COMPARE_RESULT_AREA_FULL = 5,            # 区域人员已满;area full;
    EM_COMPARE_RESULT_REPEATENTER_CHECK_FAIL = 6,    # 防反潜验证失败(没有正常出门记录再次进门);repeat enter check fail(no normal exit record, but enter again);

class EM_A_NET_EM_ACCESS_CTL_MANAGER(IntEnum):
    """
    门禁控制器操作类型
    operate type of accesscontroller
    """
    NET_EM_ACCESS_CTL_MANAGER_ADDDEVICE = 0,    # 添加单个分控器, 对应结构体 pstInParam = NET_IN_ACCESS_CTL_MANAGER_ADDDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_ADDDEVICE;add accesssubcontroller, Corresponding to pstInParam = NET_IN_ACCESS_CTL_MANAGER_ADDDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_ADDDEVICE;
    NET_EM_ACCESS_CTL_MANAGER_MODIFYDEVICE = 1, # 修改分控器名称, 对应结构体 pstInParam = NET_IN_ACCESS_CTL_MANAGER_MODIFYDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_MODIFYDEVICE;modify accesssubcontroller, Corresponding to pstInParam = NET_IN_ACCESS_CTL_MANAGER_MODIFYDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_MODIFYDEVICE;
    NET_EM_ACCESS_CTL_MANAGER_REMOVEDEVICE = 2, # 删除分控器, 对应结构体 pstInParam = NET_IN_ACCESS_CTL_MANAGER_REMOVEDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_REMOVEDEVICE;remove accesssubcontroller, Corresponding to pstInParam = NET_IN_ACCESS_CTL_MANAGER_REMOVEDEVICE, pstOutParam = NET_OUT_ACCESS_CTL_MANAGER_REMOVEDEVICE;
    NET_EM_ACCESS_CTL_GETSUBCONTROLLER_INFO = 3,    # 获取分控器信息, 对应结构体 pstInParam = NET_IN_GET_SUB_CONTROLLER_INFO, pstOutParam = NET_OUT_GET_SUB_CONTROLLER_INFO;get accesssubcontroller info, Corresponding to pstInParam = NET_IN_GET_SUB_CONTROLLER_INFO, pstOutParam = NET_OUT_GET_SUB_CONTROLLER_INFO;
    NET_EM_ACCESS_CTL_GETSUBCONTROLLER_STATE = 4,    # 获取分控器状态, 对应结构体 pstInParam = NET_IN_GET_SUB_CONTROLLER_STATE, pstOutParam = NET_OUT_GET_SUB_CONTROLLER_STATE;get accesssubcontroller state, Corresponding to pstInParam = NET_IN_GET_SUB_CONTROLLER_STATE, pstOutParam = NET_OUT_GET_SUB_CONTROLLER_STATE;
    NET_EM_ACCESS_CTL_SET_REPEAT_ENTERROUTE = 5,    # 设置反潜路径信息, 对应结构体 pstInparam = NET_IN_SET_REPEAT_ENTERROUTE, pstOutParam = NET_OUT_SET_REPEAT_ENTERROUTE;set repeat engterroute, Corresponding to pstInparam = NET_IN_SET_REPEAT_ENTERROUTE, pstOutParam = NET_OUT_SET_REPEAT_ENTERROUTE;
    NET_EM_ACCESS_CTL_GET_REPEAT_ENTERROUTE = 6,    # 获取反潜路径信息, 对应结构体 pstInparam = NET_IN_GET_REPEAT_ENTERROUTE, pstOutParam = NET_OUT_GET_REPEAT_ENTERROUTE;get repeat enterroute, Corresponding to pstInparam = NET_IN_GET_REPEAT_ENTERROUTE, pstOutParam = NET_OUT_GET_REPEAT_ENTERROUTE;
    NET_EM_ACCESS_CTL_SET_ABLOCK_ROUTE = 7,     # 设置AB互锁路径信息, 对应结构体 pstInparam = NET_IN_SET_ABLOCK_ROUTE, pstOutParam = NET_OUT_SET_ABLOCK_ROUTE;set ABLock route, Corresponding to pstInparam = NET_IN_SET_ABLOCK_ROUTE, pstOutParam = NET_OUT_SET_ABLOCK_ROUTE;
    NET_EM_ACCESS_CTL_GET_ABLOCK_ROUTE = 8,     # 获取AB互锁路径信息, 对应结构体 pstInparam = NET_IN_GET_ABLOCK_ROUTE, pstOutParam = NET_OUT_GET_ABLOCK_ROUTE;get ABLock route, Corresponding to pstInparam = NET_IN_GET_ABLOCK_ROUTE, pstOutParam = NET_OUT_GET_ABLOCK_ROUTE;
    NET_EM_ACCESS_CTL_GET_LOGSTATUS = 9,        # 获取日志同步状态,对应结构体 pstInparam = NET_IN_GET_LOGSTATUS, pstOutParam = NET_OUT_GET_LOGSTATUS;get log synchronize status, Corresponding to pstInparam = NET_IN_GET_LOGSTATUS, pstOutParam = NET_OUT_GET_LOGSTATUS;
    NET_EM_ACCESS_CTL_SYNCHRO_OFFLINE_LOG = 10, # 同步离线日志, 对应结构体 pstInparam = NET_IN_SYNCHRO_OFFLINE_LOG, pstOutParam = NET_OUT_SYNCHRO_OFFLINE_LOG;synchro offline log, Corresponding to pstInparam = NET_IN_SYNCHRO_OFFLINE_LOG, pstOutParam = NET_OUT_SYNCHRO_OFFLINE_LOG;
    NET_EM_ACCESS_CTL_SYNCHRO_TIME = 11,        # 同步分控器时间,对应结构体 pstInparam = NET_IN_SYNCHRO_CONTROLLER_TIME, pstOutParam = NET_OUT_SYNCHRO_CONTROLLER_TIME;synchro subController time,Corresponding to pstInparam = NET_IN_SYNCHRO_CONTROLLER_TIME, pstOutParam = NET_OUT_SYNCHRO_CONTROLLER_TIME;
    NET_EM_ACCESS_CTL_SET_QRCODEDECODE_INFO = 12,    # 设置二维码的解码信息, 对应结构体 pstInparam = NET_IN_SET_QRCODE_DECODE_INFO, pstOutParam = NET_OUT_SET_QRCODE_DECODE_INFO;set QRcode decode info, Corresponding to pstInparam = NET_IN_SET_QRCODE_DECODE_INFO, pstOutParam = NET_OUT_SET_QRCODE_DECODE_INFO;

class EM_A_NET_ACCESS_PROPERTY(IntEnum):
    """
    单双向
    property
    """
    NET_EM_ACCESS_PROPERTY_UNKNOWN = 0,         # 未知;unknown;
    NET_EM_ACCESS_PROPERTY_BIDIRECT = 1,        # 双向门禁;bidirect;
    NET_EM_ACCESS_PROPERTY_UNIDIRECT = 2,       # 单向门径;unidirect;

class EM_A_NET_ENUM_QRCODE_CIPHER(IntEnum):
    """
    使用的加密算法
    QRCode cipher
    """
    NET_ENUM_QRCODE_CIPHER_UNKNOWN = 0,
    NET_ENUM_QRCODE_CIPHER_AES256 = 1,          # AES-256;AES-256;

class EM_STATUS_TYPE(IntEnum):
    """
    设备导入文件状态
    Indicates the status of the imported file
    """
    EM_IMPORT_STATUS_UNKNOWN = 0,               # 未知;the unknown;
    EM_IMPORT_STATUS_BEGIN = 1,                 # 开始;begin;
    EM_IMPORT_STATUS_APPEND = 2,                # 追加;additional;
    EM_IMPORT_STATUS_END = 3,                   # 结束;end;

class EM_SECURITY_TASK_TYPE(IntEnum):
    """
    当前任务类型
    Indicates the current task type
    """
    EM_TYPE_STATUS_UNKNOWN = 0,                 # 未知;the unknown;
    EM_TYPE_STATUS_NONE = 1,                    # 当前无任务;There is no current task;
    EM_TYPE_STATUS_IMPORT = 2,                  # 有导入任务;Import task exists;
    EM_TYPE_STATUS_EXPORT = 3,                  # 有导出任务;An export task exists;

class EM_SECURITY_TASK_STATUS(IntEnum):
    """
    当前任务状态
    Indicates the current task status
    """
    EM_TASK_STATUS_UNKNOWN = 0,                 # 未知;the unknown;
    EM_TASK_STATUS_RUNNING = 1,                 # 任务执行中;The task is being executed;
    EM_TASK_STATUS_SUCCEEDED = 2,               # 任务执行成功;Task execution succeeded;
    EM_TASK_STATUS_FAILED = 3,                  # 任务执行失败;Task execution fails;

class EM_A_EXTPTZ_ControlType(IntEnum):
    """
    云台控制扩展命令
    PTZ control extensive command
    """
    EM_A_EXTPTZ_LEFTTOP = 32,                   # 左上;Upper left;
    EM_A_EXTPTZ_RIGHTTOP = 33,                  # 右上;Upper right;
    EM_A_EXTPTZ_LEFTDOWN = 34,                  # 左下;Down left;
    EM_A_EXTPTZ_RIGHTDOWN = 35,                 # 右下;Down right;
    EM_A_EXTPTZ_ADDTOLOOP = 36,                 # 加入预置点到巡航 巡航线路 预置点值;Add preset to tour tour preset value;
    EM_A_EXTPTZ_DELFROMLOOP = 37,               # 删除巡航中预置点 巡航线路 预置点值;Delete preset in tour tour preset value;
    EM_A_EXTPTZ_CLOSELOOP = 38,                 # 清除巡航 巡航线路;Delete tour tour;
    EM_A_EXTPTZ_STARTPANCRUISE = 39,            # 开始水平旋转;Begin pan rotation;
    EM_A_EXTPTZ_STOPPANCRUISE = 40,             # 停止水平旋转;Stop pan rotation;
    EM_A_EXTPTZ_SETLEFTBORDER = 41,             # 设置左边界;Set left limit;
    EM_A_EXTPTZ_SETRIGHTBORDER = 42,            # 设置右边界;Set right limit;
    EM_A_EXTPTZ_STARTLINESCAN = 43,             # 开始线扫;Begin scanning;
    EM_A_EXTPTZ_CLOSELINESCAN = 44,             # 停止线扫;Stop scanning;
    EM_A_EXTPTZ_SETMODESTART = 45,              # 设置模式开始 模式线路;Start mode mode line;
    EM_A_EXTPTZ_SETMODESTOP = 46,               # 设置模式结束 模式线路;Stop mode mode line;
    EM_A_EXTPTZ_RUNMODE = 47,                   # 运行模式 模式线路;Enable mode Mode line;
    EM_A_EXTPTZ_STOPMODE = 48,                  # 停止模式 模式线路;Unable mode Mode line;
    EM_A_EXTPTZ_DELETEMODE = 49,                # 清除模式 模式线路;Delete mode Mode line;
    EM_A_EXTPTZ_REVERSECOMM = 50,               # 翻转命令;Flip;
    EM_A_EXTPTZ_FASTGOTO = 51,                  # 快速定位 水平坐标(-8191~8191) 垂直坐标(-8191~8191) 变倍(-16~16);3D position X address(-8191~8191) Y address(-8191~8191) zoom(-16~16);
    EM_A_EXTPTZ_AUXIOPEN = 52,                  # 辅助开关开 辅助点(param4对应 PTZ_CONTROL_AUXILIARY,param1、param2、param3无效,dwStop设置为FALSE);auxiliary open Auxiliary point;
    EM_A_EXTPTZ_AUXICLOSE = 53,                 # 辅助开关关 辅助点(param4对应 PTZ_CONTROL_AUXILIARY,param1、param2、param3无效,dwStop设置为FALSE);Auxiliary close Auxiliary point;
    EM_A_EXTPTZ_OPENMENU = 54,                  # 打开球机菜单;Open dome menu;
    EM_A_EXTPTZ_CLOSEMENU = 55,                 # 关闭菜单;Close menu;
    EM_A_EXTPTZ_MENUOK = 56,                    # 菜单确定;Confirm menu;
    EM_A_EXTPTZ_MENUCANCEL = 57,                # 菜单取消;Cancel menu;
    EM_A_EXTPTZ_MENUUP = 58,                    # 菜单上;menu up;
    EM_A_EXTPTZ_MENUDOWN = 59,                  # 菜单下;menu down;
    EM_A_EXTPTZ_MENULEFT = 60,                  # 菜单左;menu left;
    EM_A_EXTPTZ_MENURIGHT = 61,                 # 菜单右;Menu right;
    EM_A_EXTPTZ_ALARMHANDLE = 64,               # 报警联动云台 parm1：报警输入通道；parm2：报警联动类型1-预置点2-线扫3-巡航；parm3：联动值,如预置点号;Alarm activate PTZ param1:Alarm input channel; param2:Alarm activation type 1-preset 2-scan 3-tour; param 3:activation value,such as preset value.;
    EM_A_EXTPTZ_MATRIXSWITCH = 65,              # 矩阵切换 parm1：预览器号(视频输出号)；parm2：视频输入号；parm3：矩阵号;Matrix switch param1:monitor number(video output number);param2:video input number;param3:matrix number;
    EM_A_EXTPTZ_LIGHTCONTROL = 66,              # 灯光控制器;Light controller;
    EM_A_EXTPTZ_EXACTGOTO = 67,                 # 三维精确定位 parm1：水平角度(0~3600)；parm2：垂直坐标(-1800-1800)；parm3：变倍(1~128),变倍为档位,并非实际变倍倍数;3D accurately positioning param1:Pan degree(0~3600); param2: tilt coordinates(-1800-1800); param3:zoom(1~128);
    EM_A_EXTPTZ_RESETZERO = 68,                 # 三维定位重设零位;Reset 3D positioning as zero;
    EM_A_EXTPTZ_MOVE_ABSOLUTELY = 69,           # 绝对移动控制命令,param4对应结构 PTZ_CONTROL_ABSOLUTELY;Absolute motion control commands, param4 corresponding struct PTZ_CONTROL_ABSOLUTELY;
    EM_A_EXTPTZ_MOVE_CONTINUOUSLY = 70,         # 持续移动控制命令,param4对应结构 PTZ_CONTROL_CONTINUOUSLY;Continuous motion control commands, param4 corresponding struct PTZ_CONTROL_CONTINUOUSLY;
    EM_A_EXTPTZ_GOTOPRESET = 71,                # 云台控制命令,以一定速度转到预置位点,parm4对应结构PTZ_CONTROL_GOTOPRESET;PTZ control command, at a certain speed to preset locus, param4 corresponding struct PTZ_CONTROL_GOTOPRESET;
    EM_A_EXTPTZ_SET_VIEW_RANGE = 73,            # 设置可视域(param4对应结构 PTZ_VIEW_RANGE_INFO);Set to horizon(param4 corresponding struct PTZ_VIEW_RANGE_INFO);
    EM_A_EXTPTZ_FOCUS_ABSOLUTELY = 74,          # 绝对聚焦(param4对应结构PTZ_FOCUS_ABSOLUTELY);Absolute focus(param4 corresponding struct PTZ_FOCUS_ABSOLUTELY);
    EM_A_EXTPTZ_HORSECTORSCAN = 75,             # 水平扇扫(param4对应PTZ_CONTROL_SECTORSCAN,param1、param2、param3无效);Level fan sweep(param4 corresponding PTZ_CONTROL_SECTORSCAN,param1,param2,param3 is invalid);
    EM_A_EXTPTZ_VERSECTORSCAN = 76,             # 垂直扇扫(param4对应PTZ_CONTROL_SECTORSCAN,param1、param2、param3无效);Vertical sweep fan(param4correspondingPTZ_CONTROL_SECTORSCAN,param1,param2,param3 is invalid);
    EM_A_EXTPTZ_SET_ABS_ZOOMFOCUS = 77,         # 设定绝对焦距、聚焦值,param1为焦距,范围:[0,255],param2为聚焦,范围:[0,255],param3、param4无效;Set absolute focus, focus on value, param1 for focal length, range: [0-255], param2 as the focus, scope: [0-255], param3, param4 is invalid;
    EM_A_EXTPTZ_SET_FISHEYE_EPTZ = 78,          # 控制鱼眼电子云台,param4对应结构 PTZ_CONTROL_SET_FISHEYE_EPTZ;Control fish eye PTZ, param4corresponding to structure PTZ_CONTROL_SET_FISHEYE_EPTZ;
    EM_A_EXTPTZ_SET_TRACK_START = 79,           # 轨道机开始控制(param4对应结构体为 PTZ_CONTROL_SET_TRACK_CONTROL,dwStop传FALSE, param1、param2、param3无效);Track start control(param4 corresponding to structure PTZ_CONTROL_SET_TRACK_CONTROL,dwStop set as FALSE, param1, param2, param3 is invalid);
    EM_A_EXTPTZ_SET_TRACK_STOP = 80,            # 轨道机停止控制(param4对应结构体为 PTZ_CONTROL_SET_TRACK_CONTROL,dwStop传FALSE,param1、param2、param3无效);Track stop control (param4 corresponding to structure PTZ_CONTROL_SET_TRACK_CONTROL,dwStop set as FALSE, param1, param2, param3 is invalid);
    EM_A_EXTPTZ_RESTART = 81,                   # 云台重启命令(param1、param2、param3 param4 均无效,dwStop设置为FALSE);To restart the PTZ(param1,param2,param3,param4 are all invalid ,dwStop set to FALSE );
    EM_A_EXTPTZ_INTELLI_TRACKMOVE = 82,         # 云台连续移动,枪球联动专用,param4对应结构 PTZ_CONTROL_INTELLI_TRACKMOVE;Continuous motion control commands,track move,param4 corresponding struct PTZ_CONTROL_INTELLI_TRACKMOVE;
    EM_A_EXTPTZ_SET_FOCUS_REGION = 83,          # 设置区域聚焦参数(param4对应结构体为PTZ_CONTROL_SET_FOCUS_REGION,dwStop传FALSE,param1、param2、param3无效);set the focus region(param4 corresponding to PTZ_CONTROL_SET_FOCUS_REGION,dwStop set to FALSE,param1,param2,param3 are all invalid);
    EM_A_EXTPTZ_PAUSELINESCAN = 84,             # 暂停线扫(param1、param2、param3param4均无效，dwStop设置为FALSE);Pause Scan(param1,param2,param3,param4 are all invalid ,dwStop set to FALSE);
    EM_A_EXTPTZ_INTELLI_SETLENSWISDOMSTATE = 85,    # 目标跟踪时设置聚焦模式(param4对应结构体为PTZ_CONTROL_INTELLI_SETLENSWISDOMSTATE,dwStop传FALSE,param1、param2、param3无效);Set focus mode when tracking target(param4 corresponding to PTZ_CONTROL_INTELLI_SETLENSWISDOMSTATE, dwStop set to FALSE,param1,param2,param3 are all invalid);
    EM_A_EXTPTZ_INTELLI_SETFOCUSAREA = 86,      # 设置聚焦区域(param4对应结构体为PTZ_CONTROL_INTELLI_SETFOCUSAREA,dwStop传FALSE,param1、param2、param3无效)/ 注：目标跟踪若不需设置聚焦区域，因聚焦区域会沿袭上次主动设置状态，故需主动调用此接口取消设置聚焦区域;Set focus area when tracking target(param4 corresponding to PTZ_CONTROL_INTELLI_SETFOCUSAREA, dwStop set to FALSE,param1,param2,param3 are all invalid)Note: if target tracking do not need set focus area,user need to set cancel by this interface;
    EM_A_EXTPTZ_UP_TELE = 112,                  # 上 + TELE param1=速度(1-8),下同;Up + TELE param1=speed (1-8);
    EM_A_EXTPTZ_DOWN_TELE = 113,                # 下 + TELE;Down + TELE;
    EM_A_EXTPTZ_LEFT_TELE = 114,                # 左 + TELE;Left + TELE;
    EM_A_EXTPTZ_RIGHT_TELE = 115,               # 右 + TELE;Right + TELE;
    EM_A_EXTPTZ_LEFTUP_TELE = 116,              # 左上 + TELE;Upper left + TELE;
    EM_A_EXTPTZ_LEFTDOWN_TELE = 117,            # 左下 + TELE;Down left + TELE;
    EM_A_EXTPTZ_TIGHTUP_TELE = 118,             # 右上 + TELE;Upper right + TELE;
    EM_A_EXTPTZ_RIGHTDOWN_TELE = 119,           # 右下 + TELE;Down right + TELE;
    EM_A_EXTPTZ_UP_WIDE = 120,                  # 上 + WIDE param1=速度(1-8),下同;Up + WIDE param1=speed (1-8);
    EM_A_EXTPTZ_DOWN_WIDE = 121,                # 下 + WIDE;Down + WIDE;
    EM_A_EXTPTZ_LEFT_WIDE = 122,                # 左 + WIDE;Left + WIDE;
    EM_A_EXTPTZ_RIGHT_WIDE = 123,               # 右 + WIDE;Right + WIDE;
    EM_A_EXTPTZ_LEFTUP_WIDE = 124,              # 左上 + WIDE;Upper left + WIDE;
    EM_A_EXTPTZ_LEFTDOWN_WIDE = 125,            # 左下 + WIDE;Down left+ WIDE;
    EM_A_EXTPTZ_TIGHTUP_WIDE = 126,             # 右上 + WIDE;Upper right + WIDE;
    EM_A_EXTPTZ_RIGHTDOWN_WIDE = 127,           # 右下 + WIDE;Down right + WIDE;
    EM_A_EXTPTZ_GOTOPRESETSNAP = 128,           # 转至预置点并抓图;goto preset and snap;
    EM_A_EXTPTZ_DIRECTIONCALIBRATION = 130,     # 校准云台方向（双方向校准）;calibtate direction(two direction);
    EM_A_EXTPTZ_SINGLEDIRECTIONCALIBRATION = 131,    # 校准云台方向（单防线校准）,param4对应结构 NET_IN_CALIBRATE_SINGLEDIRECTION;calibtate direction(single direction),param4 corresponding to structure NET_IN_CALIBRATE_SINGLEDIRECTION;
    EM_A_EXTPTZ_MOVE_RELATIVELY = 132,          # 云台相对定位,param4对应结构 NET_IN_MOVERELATIVELY_INFO;move Relatively, param4 corresponding to structure NET_IN_MOVERELATIVELY_INFO;
    EM_A_EXTPTZ_SET_DIRECTION = 133,            # 设置云台方向, param4对应结构 NET_IN_SET_DIRECTION_INFO;set PTZ Direction, param4 corresponding to NET_IN_SET_DIRECTION_INFO;
    EM_A_EXTPTZ_BASE_MOVE_ABSOLUTELY = 134,     # 精准绝对移动控制命令, param4对应结构 NET_IN_PTZBASE_MOVEABSOLUTELY_INFO（通过 CFG_CAP_CMD_PTZ 命令获取云台能力集( CFG_PTZ_PROTOCOL_CAPS_INFO )，若bSupportReal为TRUE则设备支持该操作）;Absolute motion control commands,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_INFO;
    EM_A_EXTPTZ_BASE_MOVE_CONTINUOUSLY = 135,   # 云台连续移动控制命令, param4 对应结构 NET_IN_PTZBASE_MOVE_CONTINUOUSLY_INFO. 通过 CFG_CAP_CMD_PTZ 命令获取云台能力集/ 若 CFG_PTZ_PROTOCOL_CAPS_INFO 中 stuMoveContinuously 字段的 stuType.bSupportExtra 为 TRUE, 表示设备支持该操作;Continuously motion control commands, param4 corresponding to NET_IN_PTZBASE_MOVE_CONTINUOUSLY_INFO. Through CFG_CAP_CMD_PTZ to get PTZ CapsIf CFG_PTZ_PROTOCOL_CAPS_INFO::stuMoveContinuously::stuType.bSupportExtra is TRUE, means the device supports this command;
    EM_A_EXTPTZ_BASE_SET_FOCUS_MAP_VALUE = 136, # 设置当前位置聚焦值, param4对应结构体 NET_IN_PTZBASE_SET_FOCUS_MAP_VALUE_INFO;Set focus map value, param4 corresponding to NET_IN_PTZBASE_SET_FOCUS_MAP_VALUE_INFO;
    EM_A_EXTPTZ_BASE_MOVE_ABSOLUTELY_ONLYPT = 137,    # 绝对定位独立控制PT并能以度/秒为单位的速度控制, param4对应结构 NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYPT_INFO;Absolute pt motion control commands,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYPT_INFO;
    EM_A_EXTPTZ_BASE_MOVE_ABSOLUTELY_ONLYZOOM = 138,    # 绝对定位独立控制zoom，并能控制变倍速度, param4对应结构 NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYZOOM_INFO;Absolute zoom motion control commands,param4 corresponding to NET_IN_PTZBASE_MOVEABSOLUTELY_ONLYZOOM_INFO;
    EM_A_EXTPTZ_STOP_MOVE = 139,                # 云台移动停止,同时也停止巡航模式,param4对应结构体 NET_IN_STOP_MOVE_INFO;The movement of the gimbal stops, and the cruise mode is also stopped at the same time, param4 corresponds to the structure NET_IN_STOP_MOVE_INFO;
    EM_A_EXTPTZ_START = 140,                    # 开始云台控制,param4对应结构体 NET_IN_PTZ_START_INFO;Start PTZ control,param4 corresponds to the structure NET_IN_PTZ_START_INFO;
    EM_A_EXTPTZ_STOP = 141,                     # 结束云台控制,param4对应结构体 NET_IN_PTZ_STOP_INFO;Stop PTZ control,param4 corresponds to the structure NET_IN_PTZ_STOP_INFO;
    EM_A_EXTPTZ_START_PATTERN_RECORD = 142,     # 开始模式记录,param4对应结构体 NET_IN_START_PATTERN_RECORD_INFO;Start mode recording,param4 corresponds to the structure NET_IN_START_PATTERN_RECORD_INFO;
    EM_A_EXTPTZ_STOP_PATTERN_RECORD = 143,      # 停止模式记录,param4对应结构体 NET_IN_STOP_PATTERN_RECORD_INFO;Stop mode recording,param4 corresponds to the structure NET_IN_STOP_PATTERN_RECORD_INFO;
    EM_A_EXTPTZ_START_PATTERN_REPLAY = 144,     # 开始模式回放,param4对应结构体 NET_IN_START_PATTERN_REPLAY_INFO;Start Mode Playback,param4 corresponds to the structure NET_IN_START_PATTERN_REPLAY_INFO;
    EM_A_EXTPTZ_STOP_PATTERN_REPLAY = 145,      # 停止模式回放,param4对应结构体 NET_IN_STOP_PATTERN_REPLAY_INFO;Stop Mode Playback,param4 corresponds to the structure NET_IN_STOP_PATTERN_REPLAY_INFO;
    EM_A_EXTPTZ_MOVE_DIRECTLY = 146,            # 云台三维定位, param4对应结构体 NET_IN_MOVE_DIRECTLY_INFO;Move Directly, param4 corresponds to the structure NET_IN_MOVE_DIRECTLY_INFO;
    EM_A_EXTPTZ_TOTAL = 147,                    # 最大命令值;max command value;

class EM_DETECTION_SCENE_TYPE(IntEnum):
    """
    动物检测规则下的场景类型
    Scene types under animal detection rules
    """
    EM_DETECTION_SCENE_TYPE_UNKNOWN = 0,        # 未知;Unknown;
    EM_DETECTION_SCENE_TYPE_ANIMAL = 1,         # 兽类场景，可检测动物、人、车;Animal scene, which can detect animals, people and vehicles;
    EM_DETECTION_SCENE_TYPE_BIRD = 2,           # 鸟类场景，可检测鸟类，人、车;Bird scene, which can detect birds, people and vehicles;
    EM_DETECTION_SCENE_TYPE_PIG = 3,            # 猪类场景，可检测猪只;Pig scene, can detect pigs;

class EM_A_TALK_CODING_TYPE(IntEnum):
    """
    语音编码类型
    Audio encode type
    """
    EM_A_TALK_UNKNOWN = -1,                     # 未知;unknown;
    EM_A_TALK_DEFAULT = 0,                      # 无头PCM;No-head PCM;
    EM_A_TALK_PCM = 1,                          # 带头PCM;With head PCM;
    EM_A_TALK_G711a = 2,                        # G711a;G711a;
    EM_A_TALK_AMR = 3,                          # AMR;AMR;
    EM_A_TALK_G711u = 4,                        # G711u;G711u;
    EM_A_TALK_G726 = 5,                         # G726;G726;
    EM_A_TALK_G723_53 = 6,                      # G723_53;G723_53;
    EM_A_TALK_G723_63 = 7,                      # G723_63;G723_63;
    EM_A_TALK_AAC = 8,                          # AAC;AAC;
    EM_A_TALK_OGG = 9,                          # OGG;OGG;
    EM_A_TALK_G729 = 10,                        # G729;G729;
    EM_A_TALK_MPEG2 = 11,                       # MPEG2;MPEG2;
    EM_A_TALK_MPEG2_Layer2 = 12,                # MPEG2-Layer2;MPEG2-Layer2;
    EM_A_TALK_G722_1 = 13,                      # G.722.1;G.722.1;
    EM_A_TALK_ADPCM = 21,                       # ADPCM;ADPCM;
    EM_A_TALK_MP3 = 22,                         # MP3;MP3;

class EM_VAOBJECT_ROADCONE_ACTION(IntEnum):
    """
    物体动作支持类型;Object action support types
    """
    VAOBJECT_ROADCONE_ACTION_UNKNOWN = 0,       # 未知类型;unknown type
    VAOBJECT_ROADCONE_ACTION_APPEAR = 1,        # 首次出现在检测区域或者跟踪时物理分离动作中尚未确认的新物体;New objects that have not yet been confirmed during physical separation actions that first appear in the detection area or during tracking
    VAOBJECT_ROADCONE_ACTION_MOVE = 2,          # 正在运动;Moving
    VAOBJECT_ROADCONE_ACTION_STAY = 3,          # 物体停止运动;Object stops moving
    VAOBJECT_ROADCONE_ACTION_REMOVE = 4,        # 物体从原来的区域移除，或者被遮盖，或者跟踪失败;Object removed from its original area, or obscured, or tracking failed
    VAOBJECT_ROADCONE_ACTION_DISAPPEAR = 5,     # 运动到跟踪区域之外，或者达到了算法跟踪物体的上限而被清除，消失的物体ID将不再出现;If it moves outside the tracking area or reaches the upper limit of the algorithm's tracking object and is cleared, the disappearing object ID will no longer appear
    VAOBJECT_ROADCONE_ACTION_SPLIT = 6,         # 从其他物体中分离出来;Separate from other objects
    VAOBJECT_ROADCONE_ACTION_MERGE = 7,         # 合并到其他物体;Merge to other objects
    VAOBJECT_ROADCONE_ACTION_RENAME = 8,        # 暂时使用的新的ID;Temporarily used new ID

class EM_DRIVING_DIRECTION(IntEnum):
    """
    车辆行驶方向;The direction of driving
    """
    DRIVING_DIRECTION_UNKNOWN = 0,              # 未知;Unknown
    DRIVING_DIRECTION_IN = 1,                   # 驶入;In
    DRIVING_DIRECTION_OUT = 2,                  # 驶出;Out

class EM_PARKINGSPACE_STATUS(IntEnum):
    """
    综合状态;all parking space status
    """
    PARKINGSPACE_STATUS_UNKNOWN = 0,            # 
    PARKINGSPACE_STATUS_BUSY = 1,               # 占用;busy
    PARKINGSPACE_STATUS_FREE = 2,               # 空闲;free
    PARKINGSPACE_STATUS_OVERLINE = 3,           # 压线;overline

class EM_CAR_DOOR_STATE(IntEnum):
    """
    车门状态;car door state
    """
    CAR_DOOR_STATE_UNKNOWN = 0,                 # 未知;unknown
    CAR_DOOR_STATE_OPEN = 1,                    # 开启;open
    CAR_DOOR_STATE_CLOSE = 2,                   # 关闭;close

class EM_PERSON_INTRUDE_STATUS(IntEnum):
    """
    人员闯入报警标志;Personnel intrusion alarm sign
    """
    PERSON_INTRUDE_STATUS_UNKNOWN = -1,         # 未知;unknown
    PERSON_INTRUDE_STATUS_UNMANNED = 0,         # 无人员闯入;No one broke in
    PERSON_INTRUDE_STATUS_SOMEONE = 1,          # 有人员闯入;Someone broke in

class EM_SENSOR_TYPE(IntEnum):
    """
    传感器类型;Sensor type
    """
    SENSOR_TYPE_UNKNOWN = 0,                    # 未知;Unknown
    SENSOR_TYPE_NC = 1,                         # 常闭;NC
    SENSOR_TYPE_NO = 2,                         # 常开;NO

class EM_MATCH_TWO_FACE_TYPE(IntEnum):
    """
    比对方式;comparison mode
    """
    MATCH_TWO_FACE_TYPE_UNKNOWN = 0,            # 未知;unknown
    MATCH_TWO_FACE_TYPE_PIC = 1,                # 图片比对;Image comparison
    MATCH_TWO_FACE_TYPE_EIGENVALUE = 2,         # 特征值比对;Eigenvalue comparison

class NET_CAPTURE_FORMATS(IntEnum):
    """
    抓图类型 CLIENT_CapturePictureEx 接口使用;Catch a figure type CLIENT_CapturePictureEx interface using
    """
    CAPTURE_BMP = 0,                            # BMP;BMP
    CAPTURE_JPEG = 1,                           # 100%质量的JPEG;100% quality JPEG
    CAPTURE_JPEG_70 = 2,                        # 70%质量的JPEG;70% quality JPEG
    CAPTURE_JPEG_50 = 3,                        # 50%质量的JPEG;50% quality JPEG
    CAPTURE_JPEG_30 = 4,                        # 30%质量的JPEG;30% quality JPEG
    CAPTURE_JPEG_10 = 5,                        # 10%质量的JPEG;10% quality JPEG

class EM_DECODE_FRAME_TYPE(IntEnum):
    """
    解码帧类型;the decode frame type
    """
    FRAME_TYPE_UNKNOWN = -1,                    # 未知的;unknown
    FRAME_TYPE_VIDEO = 0,                       # 视频帧;video
    FRAME_TYPE_AUDIO = 1,                       # 音频帧;audio

class NET_EM_DIAL_STATE(IntEnum):
    """
    表盘状态;dial state
    """
    DIAL_STATE_UNKNOWN = 0,                     # 未知;unknown
    DIAL_STATE_NORMAL = 1,                      # 正常;normal
    DIAL_STATE_DIM = 2,                         # 模糊;dim
    DIAL_STATE_DIAL_BROKEN = 3,                 # 表盘破损;dial broken
    DIAL_STATE_SHELL_BROKEN = 4,                # 外壳破裂;shell broken
    DIAL_STATE_ABNORMAL_READING = 5,            # 读数异常;abnormal reading

class NET_EM_DIAL_STATE(IntEnum):
    """
    表盘状态;dial state
    """
    DIAL_STATE_UNKNOWN = 0,                     # 未知;unknown
    DIAL_STATE_NORMAL = 1,                      # 正常;normal
    DIAL_STATE_DIM = 2,                         # 模糊;dim
    DIAL_STATE_DIAL_BROKEN = 3,                 # 表盘破损;dial broken
    DIAL_STATE_SHELL_BROKEN = 4,                # 外壳破裂;shell broken
    DIAL_STATE_ABNORMAL_READING = 5,            # 读数异常;abnormal reading

class NET_VIDEOSTREAM_TYPE(IntEnum):
    """
    解码回调格式;decode callback type
    """
    VIDEOSTREAM_NORMAL = 0,                     # 默认格式;normal
    VIDEOSTREAM_YUV = 1,                        # YUV格式;YUV

class NET_RADIOMETRY_RESULT(IntEnum):
    """
    热成像测温点报警结果值类型;thermal Temperature Monitoring spot alarm result value type
    """
    RADIOMETRY_RESULT_UNKNOWN = 0,              # 
    RADIOMETRY_RESULT_VAL = 1,                  # 具体值;concrete value
    RADIOMETRY_RESULT_MAX = 2,                  # 最大;max
    RADIOMETRY_RESULT_MIN = 3,                  # 最小;min
    RADIOMETRY_RESULT_AVR = 4,                  # 平均;average
    RADIOMETRY_RESULT_STD = 5,                  # 标准;standard
    RADIOMETRY_RESULT_MID = 6,                  # 中间;middle
    RADIOMETRY_RESULT_ISO = 7,                  # ISO;ISO
    RADIOMETRY_RESULT_DIFF = 8,                 # 温差;difference
    RADIOMETRY_RESULT_SLOPE = 9,                # 斜率;slope

class NET_RADIOMETRY_ALARMCONTION(IntEnum):
    """
    热成像测温点报警条件;thermal Temperature Monitoring spot alarm condition
    """
    RADIOMETRY_ALARMCONTION_UNKNOWN = 0,        # 
    RADIOMETRY_ALARMCONTION_BELOW = 1,          # 小于;below
    RADIOMETRY_ALARMCONTION_MATCH = 2,          # 等于;equal
    RADIOMETRY_ALARMCONTION_ABOVE = 3,          # 大于;above

class NET_TEMPERATURE_UNIT(IntEnum):
    """
    温度单位;temperature unit
    """
    TEMPERATURE_UNIT_UNKNOWN = 0,               # 
    TEMPERATURE_UNIT_CENTIGRADE = 1,            # 摄氏度;Centigrade
    TEMPERATURE_UNIT_FAHRENHEIT = 2,            # 华氏度;Fahrenheit

class EM_CFG_BUILDING_SYSTEM_TYPE(IntEnum):
    """
    系统类型;System type
    """
    CFG_BUILDING_SYSTEM_TYPE_UNKNOWN = 0,       # 未知;Unknown
    CFG_BUILDING_SYSTEM_TYPE_DIGITAL = 1,       # 数字系统;Digital system
    CFG_BUILDING_SYSTEM_TYPE_ANALOG = 2,        # 模拟系统;Analog system

class NET_CFG_VTO_TYPE(IntEnum):
    """
    VTO设备类型;VTO device type
    """
    CFG_VTO_TYPE_UNKNOWN = 0,                   # 未知;unknown
    CFG_VTO_TYPE_VILLA = 1,                     # 1 别墅机;1 villa
    CFG_VTO_TYPE_DOOR = 2,                      # 2 门口机;2 VTO
    CFG_VTO_TYPE_LADDER = 3,                    # 3 梯控机;3 ladder
    CFG_VTO_TYPE_APART = 4,                     # 4 模块化门口机;4 Small Apartment
    CFG_VTO_TYPE_SECOND = 5,                    # 5 二次确认机;5 second Confirmation
    CFG_VTO_TYPE_FACE = 6,                      # 6 目标录入机;6 Target Input Device
    CFG_VTO_TYPE_CONTROLLER = 7,                # 7 控制器;7 Controller
    CFG_VTO_TYPE_MAX = 8,                       # 

class EM_CFG_VTO_TYPE(IntEnum):
    """
    门口机类型;VTO type
    """
    CFG_VTO_TYPE_UNKNOW = 0,                    # 未知;unknown
    CFG_VTO_TYPE_VTO = 1,                       # 单元门口机;unit VTO
    CFG_VTO_TYPE_WALL = 2,                      # 围墙机;fence station
    CFG_VTO_TYPE_MAX = 3,                       # 

class EM_CFG_ROOM_RULE(IntEnum):
    """
    门口机呼叫规则;Room Rule
    """
    CFG_ROOM_RULE_UNKNOW = 0,                   # 未知;unknow
    CFG_ROOM_RULE_SERIAL = 1,                   # Serial 连续房间号，有些国外使用1~100的房号;Serial room
    CFG_ROOM_RULE_NOSERIAL = 2,                 # NoSerial 非连续房间号，比如国内的301,502;No Serial room

class EM_VIDEO_STANDARD(IntEnum):
    """
    视频制式;video standard
    """
    VIDEO_STANDARD_UNKNOWN = 0,                 # 
    VIDEO_STANDARD_PAL = 1,                     # "PAL";"PAL"
    VIDEO_STANDARD_NTSC = 2,                    # "NTSC";"NTSC"
    VIDEO_STANDARD_SECAM = 3,                   # "SECAM";"SECAM"

class NET_EM_REGISTAR_SERVER_TYPE(IntEnum):
    """
    服务器类型;server type
    """
    REGISTAR_SERVER_TYPE_UNKNOWN = 0,           # 
    REGISTAR_SERVER_TYPE_VTO = 1,               # 
    REGISTAR_SERVER_TYPE_H500 = 2,              # 
    REGISTAR_SERVER_TYPE_VTNC = 3,              # 
    REGISTAR_SERVER_TYPE_ZYCOO = 4,             # 
    REGISTAR_SERVER_TYPE_THIRDPARTY = 5,        # 
    REGISTAR_SERVER_TYPE_3CXSYSTEM = 6,         # 
    REGISTAR_SERVER_TYPE_ASTERISK = 7,          # 

class EM_MASK_DETECT_RESULT_TYPE(IntEnum):
    """
    口罩检测结果类型;Test result type of respirator
    """
    MASK_DETECT_TYPE_UNKNOWN = 0,               # 未知;Unknown
    MASK_DETECT_TYPE_NO_MASK = 1,               # 未戴口罩;No mask
    MASK_DETECT_TYPE_WEAR_MASK = 2,             # 戴口罩;Wear mask

class EM_CFG_VTH_TYPE(IntEnum):
    """
    室内机类型;device usa scene
    """
    CFG_VTH_TYPE_UNKNOW = 0,                    # 未知;unknown
    CFG_VTH_TYPE_MAIN = 1,                      # 主室内机;main VTH
    CFG_VTH_TYPE_SUB = 2,                       # 子室内机;extension

class EM_CFG_VTH_APPTYPE(IntEnum):
    """
    设备使用场景;device Using Scene
    """
    CFG_VTH_APPTYPE_UNKNOW = 0,                 # 未知;Unknown
    CFG_VTH_APPTYPE_COMMON = 1,                 # 正常室内机;normal indoor unit
    CFG_VTH_APPTYPE_MANAGER = 2,                # 管理中心;Management Center

class EM_SUPPORT_RPC_TYPE(IntEnum):
    """
    支持json传参的接口;Interface that supports JSON parameters
    """
    FINDNEXTFILEEX_DH_FILE_QUERY_FACE = 0,      # CLIENT_FindNextFileEx + FILE_QUERY_FACE, 入参对应结构体NET_FINDNEXTFILEEX_FILE_QUERY_FACE_IN_PARAMS，出参对应结构体NET_FINDNEXTFILEEX_FILE_QUERY_FACE_OUT_PARAMS;CLIENT_FindNextFileEx + FILE_QUERY_FACE, the input corresponds to the struct NET_FINDNEXTFILEEX_FILE_QUERY_FACE_IN_PARAMS, and the output corresponds to the struct NET_FINDNEXTFILEEX_FILE_QUERY_FACE_OUT_PARAMS

class EM_HAS_RAINCOAT(IntEnum):
    """
    是否有雨披;Whether has raincoat
    """
    HAS_RAINCOAT_UNKNOWN = 0,                   # 未知;UNKNOWN
    HAS_RAINCOAT_NO = 1,                        # 无;NO
    HAS_RAINCOAT_YES = 2,                       # 有;YES

class EM_ASSOCIATED_RECORD_SOURCE(IntEnum):
    """
    是否与其他目标关联;Whether is associated with record source
    """
    ASSOCIATED_RECORD_SOURCE_UNKNOWN = -1,      # 未知;UNKNOWN
    ASSOCIATED_RECORD_SOURCE_NONE = 0,          # 未关联;None
    ASSOCIATED_RECORD_SOURCE_HUMAN = 1,         # 与人体有关联成功;human
    ASSOCIATED_RECORD_SOURCE_MOTOR_VEHICLE_PASSING = 2,    # 与机动车过车有关联;motor vehicle passing
    ASSOCIATED_RECORD_SOURCE_MOTOR_VEHICLE_VIOLATION = 3,    # 与机动车违章有关联;motor vehicle violation
    ASSOCIATED_RECORD_SOURCE_STRUCTURED_MOTOR_VEHICLE = 4,    # 与结构化机动车有关联;structured motor vehicle
    ASSOCIATED_RECORD_SOURCE_FACE = 5,          # 与目标有关联;Target
    ASSOCIATED_RECORD_SOURCE_NON_MOTOR_VEHICLE = 6,    # 与非机动车有关联;non-motor vehicle

class EM_SHOES_TYPE(IntEnum):
    """
    鞋子类型;shoes type
    """
    SHOES_UNKNOWN = 0,                          # 未知;unknown
    SHOES_LEATHER = 1,                          # 皮鞋;leather
    SHOES_BOOTS = 2,                            # 靴子;boots
    SHOES_CASUAL = 3,                           # 休闲鞋;casual
    SHOES_SANDALS = 4,                          # 凉鞋;sandals
    SHOES_SNEAKERS = 5,                         # 运动鞋;sneakers
    SHOES_SLIPPER = 6,                          # 拖鞋;slipper
    SHOES_OTHERS = 7,                           # 其他;others
    SHOES_SHOECOVER = 8,                        # 鞋套;shoe cover

class EM_LIGHT_SCENE(IntEnum):
    """
    光照场景类型;Illumination Scene Type
    """
    LIGHT_SCENE_UNKNOWN = 0,                    # 未知;Unknown
    LIGHT_SCENE_DAY = 1,                        # 白天;Day
    LIGHT_SCENE_NIGHT = 2,                      # 夜晚;Night
    LIGHT_SCENE_NORMAL = 3,                     # 普通;Normal
    LIGHT_SCENE_FRONT_LIGHT = 4,                # 顺光;Front light
    LIGHT_SCENE_BACK_LIGHT = 5,                 # 一般逆光;General back light
    LIGHT_SCENE_STRONG_LIGHT = 6,               # 强逆光;Strong light
    LIGHT_SCENE_LOW_LIGHT = 7,                  # 低照度;Low light
    LIGHT_SCENE_CUSTOM = 8,                     # 自定义;Custom

class EM_TANK_STATUS(IntEnum):
    """
    贮柜当前状态;Tank Status
    """
    TANK_STATUS_UNKNOWN = 0,                    # 未知;Unknown
    TANK_STATUS_DISCHARGING = 1,                # 出料;Discharging
    TANK_STATUS_CHARGING = 2,                   # 进料;Charging
    TANK_STATUS_IDLE = 3,                       # 空闲;Idle

class EM_OPTIMIZE_TYPE(IntEnum):
    """
    SDK设置内部优化方案;NetSDK optimize type
    """
    OPT_TYPE_DEFAULT = 0,                       # 默认不优化;default to do nothing
    OPT_TYPE_MOBILE_V1 = 1,                     # 和选项 EM_OPT_TYPE_MOBILE_OPTION冲突，两者只能使用一个，不支持异步登陆优化, 手机使用优化,开启后，默认过滤设备属性和硬盘信息.;optimized for mobile,conflict with the EM_OPT_TYPE_MOBILE_OPTION option
    OPT_TYPE_P2P_NETPARAM_V1 = 2,               # P2P网络参数设置，pParam 为 NET_PARAM*;the set for P2P network param,  pParam's type is  NET_PARAM*
    OPT_TYPE_MOBILE_OPTION = 3,                 # 和选项 EM_OPT_TYPE_MOBILE_V1冲突，两者只能使用一个,支持异步登陆优化, 手机优化选项, 参数int, 按位从低到高, 传入的值参考枚举类型 EM_OPTTYPE_MOBILE_TYPE;conflict with the EM_OPT_TYPE_MOBILE_V1 option ,  mobile optimize option, value type int, bit value from low to high, see Enum EM_OPTTYPE_MOBILE_TYPE
    OPT_TYPE_LOGIN_GET_ENCRYPT = 4,             # 登录时获取秘钥信息，减少拉流耗时，pParam 为int*， 1表示开启优化;Obtain secret key information during login to reduce streaming time. The parameter pParam is an int*, with 1 indicating optimization enabled

class EM_OPTTYPE_MOBILE_TYPE(IntEnum):
    """
    手机登陆时过滤可选方式,按照类型进行|或操作。;APP filter login optimize type,operate |
    """
    OPTTYPE_MOBILE_DEVICE_ATTR = 1,             # 设备属性;device info
    OPTTYPE_MOBILE_DEVICE_SN = 2,               # 设备序列号;device sequence
    OPTTYPE_MOBILE_DISK_INFO = 4,               # 硬盘信息;hard info
    OPTTYPE_MOBILE_DIGITAL_NUM = 8,             # 数字通道个数;digital num
    OPTTYPE_MOBILE_ALARM_IO = 16,               # 报警输入输出;Alarm IO number
    OPTTYPE_MOBILE_DEVICE_ABILITY = 32,         # 能力集;Device ability
    OPTTYPE_MOBILE_STATE_SOFTWARE = 4096,       # 查询软件版本信息APP优化;query software APP option

class EM_NET_SCADA_POINT_TYPE(IntEnum):
    """
    点位类型;Spot type
    """
    SCADA_POINT_TYPE_UNKNOWN = 0,               # 未知;unknown
    SCADA_POINT_TYPE_ALL = 1,                   # 所有类型;all type
    SCADA_POINT_TYPE_YC = 2,                    # 遥测 模拟量输入;analog input
    SCADA_POINT_TYPE_YX = 3,                    # 遥信 开关量输入;switch input
    SCADA_POINT_TYPE_YT = 4,                    # 遥调 模拟量输出;analog output
    SCADA_POINT_TYPE_YK = 5,                    # 遥控 开关量输出;switch ouput

class EM_TITLE_POSITON(IntEnum):
    """
    OSD显示位置;The OSD display position.
    """
    TITLE_POSITON_UNKNOW = 0,                   # 未知;Unknown
    TITLE_POSITON_RIGHTUP = 1,                  # 右上角;Upper right corner
    TITLE_POSITON_LEFTUP = 2,                   # 左上角;Upper left corner
    TITLE_POSITON_LEFTDOWN = 3,                 # 左下角;Lower left corner
    TITLE_POSITON_RIGHTDOWN = 4,                # 右下角;Lower right corner

