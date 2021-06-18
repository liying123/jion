#if 0
/*---type3---*/
extern char COLLECTION_EQUIPMENT_ID3[21] = "采集设备编号";		/*1采集设备编号*/
extern char NETBAR_WACODE3[14] = "场所编号";                            /*2场所编号*/
extern char COLLECTION_EQUIPMENT_LONGITUDE3[10] = "采集设备经度";       /*3采集设备经度*/
extern char COLLECTION_EQUIPMENT_LATITUDE3[10] = "采集设备纬度";        /*4采集设备纬度*/

/*---type4---*/
extern char NETBAR_WACODE4[14] = "场所编号";                            /*1场所编号*/
extern char COLLECTION_EQUIPMENT_ID4[21] = "采集设备编号";              /*2采集设备编号*/
extern char OLLECTION_EQUIPMENT_NAME4[128] = "采集设备名称";            /*3采集设备名称:设备名称*/
extern char COLLECTION_EQUIPMENT_ADRESS4[256] = "设备地址";             /*4设备地址:地址信息*/
extern int  COLLECTION_EQUIPMENT_TYPE4 = 1;                             /*5采集设备类型*/
extern char SECURITY_SOFTWARE_ORGCODE4[9] = "厂商代码";                 /*6安全厂商组织机构代码:组织机构代码*/
extern char COLLECTION_EQUIPMENT_LONGITUDE4[10] = "采集经度";       /*7采集设备经度*/
extern char COLLECTION_EQUIPMENT_LATITUDE4[10] = "设备纬度";        /*8采集设备纬度*/
extern int UPLOAD_TIME_INTERVAL4 = 24*60*60;                            /*9上传数据间隔时间:数据上传采集间隔，单位秒（s）*/
extern int COLLECTION_RADIUS4 = 150;                                    /*10采集半径:单位米（m）*/
extern char VEHICLE_CODE4[64] = "车牌号码";                             /*11车牌号码*/
extern char SUBWAY_LINE_INFO4[256] = "地铁线路信息";                    /*12地铁线路信息*/
extern char SUBWAY_VEHICLE_INFO4[256] = "地铁车辆信息";                 /*13地铁车辆信息*/
extern char SUBWAY_COMPARTMENT_NUMBER4[256] = "地铁车厢编号";           /*14地铁车厢编号*/

/*---type5---*/
extern char NETBAR_WACODE5[14] = "上网场所编码";                /*1上网服务场所编码*/
extern char PLACE_NAME5[256] = "场所名称";                      /*2上网服务场所名称:场所名称*/
extern char SITE_ADDRESS5[256] = "地址信息";                    /*3场所详细地址（包括省市区县路/弄号）:地址信息*/
extern char LONGITUDE5[10] = "场所经度";                        /*4场所经度*/
extern char LATITUDE5[10] = "场所纬度";                         /*5场所纬度*/
extern char NETSITE_TYPE5[1] = "";                              /*6场所服务类型*/
extern char BUSINESS_NATURE5[1] = "0";                          /*7场所经营性质:0,表示经营;1.表示非经营;3,其他*/
extern char LAW_PRINCIPAL_NAME5[128] = "法人姓名";              /*8场所经营法人:法人姓名*/
extern char LAW_PRINCIPAL_CERTIFICATE_TYPE5[3] = "";            /*9经营法人有效证件类型:证件类型*/
extern char LAW_PRINCIPAL_CERTIFICATE_ID5[128] = "证件号码";    /*10经营法人有效证件号码:证件号码*/
extern char RELATIONSHIP_ACCOUNT5[128] = "手机/座机号码";       /*11联系方式:手机/座机号码*/
extern char START_TIME5[5] = "08:00";                           /*12营业开始时间:hh:mm,如：08：00*/
extern char END_TIME5[5] = "22:30";                             /*13营业结束时间:hh:mm，如：22：35*/
extern char SECURITY_SOFTWARE_ORGCODE5[9] = "机构代码";         /*14厂商组织机构代码:组织机构代码*/

/*---type6---*/
extern char SECURITY_SOFTWARE_ORGNAME6[70] = "厂商名称";        /*1厂商名称*/
extern char SECURITY_SOFTWARE_ORGCODE6[9] = "机构代码";         /*2厂商组织机构代码:组织结构代码*/
extern char SECURITY_SOFTWARE_ADDRESS6[256] = "厂商地址";      /*3厂商地址*/
extern char CONTACTOR6[128] = "厂商联系人";                     /*4联系人:厂商联系人*/
extern char CONTACTOR_TEL6[128] = "电话号码";                   /*5联系人电话:电话号码*/
extern char CONTACTOR_MAIL6[32] = "电子邮件地址";               /*6联系人邮件:电子邮件地址*/

/*---type7---*/
extern char NETBAR_WACODE7[14] = "场所代码";            /*场所代码*/
extern char COLLECTION_EQUIPMENT_ID7[21] = "设备代码";  /*设备代码*/
extern char STATUS_CODE7[2] = "01";                     /*01 在线；99 其他*/
#endif


















