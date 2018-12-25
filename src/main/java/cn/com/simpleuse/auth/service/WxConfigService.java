package cn.com.simpleuse.auth.service;

public interface WxConfigService {
    String getAppId();
    String getSecret();
    String getToken();
    String getAccessToken(String appId);
    String getMpWebRedirectUri(String appId,String redirectUri,String scope,String state);
    String getMpOpenId(String code,String state);
}
