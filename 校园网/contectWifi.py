# -*-coding:utf-8-*-

import os
import pywifi
from pywifi import const
import campus_network_client
from time import sleep
import json

def configInit(basedir,name):
    configPath=basedir+"/{}".format(name)
    if not os.path.exists(configPath):
        config={"wifi_name":"必填项","useClient":1,"password":""}
        with open(configPath,'w',encoding='utf-8') as fp:
            json.dump(config,fp,ensure_ascii=False)
        help='''初始化完毕，请按要求填写信息\nwifi_name为wifi名字，useClient指使用网络客户端,wifi密码写了就会使用密码非\n以上信息在已生成的{}文件中,按任意键退出去修改此文件'''.format(name)
        
        with open(basedir+"/{}".format("{}_help.txt".format(name.replace(".json",""))),'w',encoding='utf-8') as fp:
            fp.write(help)
        input(help)
        1/0
    with open(configPath,'r',encoding='utf-8') as fp:
        config=json.loads(fp.read())
    return config


# 1、python连接WiFi，需要使用pywifi包，安装pywifi：pip install pywifi
#注意：如果提示找不到comtypes，则还需要安装pip install comtypes
# 2、判断wifi连接状态：
def wifi_connect_status(iface):
    if iface.status() in [const.IFACE_CONNECTED, const.IFACE_INACTIVE]:
        return 1
    return 0
def print_connect_status(result_code):
    if result_code==1:
        print("wifi connected!")
    else:
        print("wifi not connected!")

# 3、扫描wifi：
def scan_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()
    sleep(1)
    scans_res = iface.scan_results()
    print("wifi scan result:")
    show_scans_wifi_list(scans_res)
    return scans_res
#显示wifi列表
def show_scans_wifi_list(scans_res,wifi_name):
    max=-1
    for index,wifi_info in enumerate(scans_res):
        if  wifi_info.ssid!=wifi_name:
            continue
        # print("| %s | %s | %s | %s \n"%(index,wifi_info.ssid,wifi_info.bssid,wifi_info.signal))
        if max==-1:
            max=index
            continue
        if scans_res[max].signal<wifi_info.signal:
            max=index
    print("wifi signal max:%s,signal:%s"%(scans_res[max].ssid,scans_res[max].signal))
    return scans_res[max]

#检测等待wifi
def wait_connect(flag=1,time=60,timeUnit=1):
    count=0
    if flag!=1:
        flag=0
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # acquire the first Wlan card,maybe not
    is_connect=wifi_connect_status(iface)
    print_connect_status(is_connect)
    print("心跳时间为{}s,检测中...".format(timeUnit))
    while is_connect!=flag and (count<time or time==-1):
        is_connect=wifi_connect_status(iface)
        count+=1
        sleep(timeUnit)
    print_connect_status(is_connect)
    return is_connect
# 4、连接指定的wifi：
def connect_wifi(wifi_name,wifi_password=""):
    wifi = pywifi.PyWiFi()
    ifaces = wifi.interfaces()[0]
    print(ifaces.name())  # 输出无线网卡名称
    print_connect_status(wifi_connect_status(ifaces))
    ifaces.disconnect()
    wait_connect(flag=0)
    print('--------')
    
    profile = pywifi.Profile()  # 配置文件
    profile.ssid = wifi_name  # wifi名称
    if wifi_password!="":
        profile.auth = const.AUTH_ALG_OPEN  # 需要密码
        profile.akm.append(const.AKM_TYPE_WPA2PSK)  # 加密类型
        profile.cipher = const.CIPHER_TYPE_CCMP  # 加密单元
        profile.key = wifi_password  # wifi密码
        # ifaces.remove_all_network_profiles()  # 删除其它配置文件
    tmp_profile = ifaces.add_network_profile(profile)  # 加载配置文件
    ifaces.connect(tmp_profile)
    wait_connect(flag=1)
    isok = True
    if ifaces.status() == const.IFACE_CONNECTED:
        print("connect successfully!")
    else:
        print("connect failed!")
        isok = False
    # time.sleep(1)
    return isok

#5、连接指定的wifi,并调用登陆器
def main():
    print("start")
    config=configInit(campus_network_client.app_path(),"wifi.json")
    wifi_name=config['wifi_name']
    useClient=config['useClient']
    password=config['password']
    while True:
        # scan_wifi()
        is_ok=connect_wifi(wifi_name,password)
        if not is_ok:
            wifi_name=input("请检查wifi名并重新输入:")
            continue
        print("finish!")
        if useClient==1:
            campus_network_client.main(is_continue=-1)
        wait_connect(flag=0,time=-1,timeUnit=3)

if __name__ == "__main__":
    main()
    
    
