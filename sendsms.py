from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException 
from tencentcloud.sms.v20190711 import sms_client, models

def SendSMS(Time,Hostname,Message):
	try: 
		cred = credential.Credential("APIkey", "APIsecret") 
		httpProfile = HttpProfile()
		httpProfile.endpoint = "sms.tencentcloudapi.com"
		clientProfile = ClientProfile()
		clientProfile.httpProfile = httpProfile
		client = sms_client.SmsClient(cred, "ap-shanghai", clientProfile) 
		req = models.SendSmsRequest()
		PhoneNumber = "your_phone_number"
		TemplateID = "your_templateID"
		Arg1 = Time
		Arg2 = Hostname
		Arg3 = Message
		params = '{"PhoneNumberSet":["+86'+ PhoneNumber +'"],"TemplateID":"'+ TemplateID +'","Sign":"your_sms_sign","TemplateParamSet":[" '+ Arg1 +' "," '+ Arg2 +' "," '+ Arg3 +' "],"SmsSdkAppid":"1400071610"}'
		req.from_json_string(params)

		resp = client.SendSms(req) 
		print(resp.to_json_string()) 

	except TencentCloudSDKException as err: 
		print(err)
