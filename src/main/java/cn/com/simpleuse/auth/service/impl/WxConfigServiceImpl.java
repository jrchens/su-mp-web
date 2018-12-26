package cn.com.simpleuse.auth.service.impl;

import cn.com.simpleuse.auth.service.WxConfigService;
import com.google.common.base.Charsets;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Base64Utils;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.util.Map;

@Service
public class WxConfigServiceImpl implements WxConfigService {
    private static final Logger logger = LoggerFactory.getLogger(WxConfigServiceImpl.class);
    private static final Gson gson = new Gson();
    private String appId;
    private String secret;
    private String token;

    @Override
    @Transactional
    public String getMpOpenId(String code, String state) {
        try {
            CloseableHttpClient httpclient = HttpClients.createDefault();
            try {
                String pattern = "yyyy-MM-dd HH:mm:ss";
                DateTime now = DateTime.now();
                HttpGet httpget = new HttpGet(String.format("https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code", getAppId(), getSecret(), code));
                CloseableHttpResponse response = httpclient.execute(httpget);
                try {
                    HttpEntity entity = response.getEntity();
                    String result = FileCopyUtils.copyToString(new InputStreamReader(entity.getContent()));
                    Map<String, String> map = gson.fromJson(result, new TypeToken<Map<String, String>>() {
                    }.getType());

                    String openid = map.get("openid");
                    map.put("is_deleted", "0");
                    map.put("crtime", now.toString(pattern));
                    if (StringUtils.hasText(openid)) {
                        double step = 0.75d;
                        int expires_in = Integer.parseInt(map.get("expires_in"));
                        DateTime expiresTime = now.plusSeconds(new BigDecimal(String.valueOf(expires_in)).multiply(new BigDecimal(step)).intValue());
                        map.put("expires_time", expiresTime.toString(pattern));
                        map.put("refresh_token_expires_time", now.minusHours(1).plusDays(30).toString(pattern));


                        int cnt = jdbcTemplate.queryForObject("select count(1) from mp_web_access_token where is_deleted = ? and openid = ?", Integer.class, false, openid).intValue();
                        if (cnt > 0) {
                            jdbcTemplate.update("update mp_web_access_token set is_deleted = ? where is_deleted = ? and openid = ?", true, false, openid);
                        }
                    } else {
                        logger.error("WxConfigServiceImpl.getMpOpenId.error {}", result);
                    }

                    StringBuffer buffer = new StringBuffer();
                    buffer.append("INSERT INTO mp_web_access_token ( ");
                    buffer.append(" appid, access_token, expires_time ");
                    buffer.append(", refresh_token, refresh_token_expires_time, openid ");
                    buffer.append(", scope, errcode, errmsg ");
                    buffer.append(", is_deleted, crtime ");
                    buffer.append(") VALUES ( ");
                    buffer.append(" ?,?,? ");
                    buffer.append(",?,?,? ");
                    buffer.append(",?,?,? ");
                    buffer.append(",?,? ");
                    buffer.append(") ");

                    jdbcTemplate.update(buffer.toString(),
                            getAppId(), map.get("access_token"), map.get("expires_time")
                            , map.get("refresh_token"), map.get("refresh_token_expires_time"), map.get("openid")
                            , map.get("scope"), map.get("errcode"), map.get("errmsg")
                            , map.get("is_deleted"), map.get("crtime")
                    );

                    return openid;
                } finally {
                    response.close();
                }
            } finally {
                httpclient.close();
            }

        } catch (Exception e) {
            logger.error("WxConfigServiceImpl.getMpOpenId.error", e);
            throw new RuntimeException("mp.service.error");
        }
    }

    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setDataSource(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @PostConstruct
    public void init() {
        try {
            logger.info("WxConfigServiceImpl init method start");
            if (this.appId == null) {
                this.appId = jdbcTemplate.queryForObject("select conf_value from mp_conf where conf_code = ?", String.class, "MP_APP_ID");
                setAppId(appId);
            }
            logger.info("appId:{}",appId);
            if (this.secret == null) {
                this.secret = jdbcTemplate.queryForObject("select conf_value from mp_conf where conf_code = ?", String.class, "MP_APP_SECRET");
                setSecret(secret);
            }
            logger.info("secret:{}",secret);
            if (this.token == null) {
                this.token = jdbcTemplate.queryForObject("select conf_value from mp_conf where conf_code = ?", String.class, "MP_APP_TOKEN");
                setToken(token);
            }
            logger.info("token:{}",token);
            logger.info("WxConfigServiceImpl init method end");
        } catch (Exception e) {
            logger.error("WxConfigServiceImpl init method error", e);
        }
    }


    @Override
    public String getAppId() {
        return appId;
    }

    @Override
    public String getSecret() {
        return secret;
    }

    @Override
    public String getToken() {
        return token;
    }

    public void setAppId(String appId) {
        this.appId = appId;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Override
    public String getAccessToken(String appId) {
        try {
            return jdbcTemplate.queryForObject("select access_token from mp_access_token where is_deleted = ? and appid = ? order by id desc limit 1", String.class, false, appId);
        } catch (Exception e) {
            logger.error("WxConfigServiceImpl getAccessToken method error", e);
        }
        return null;
    }

    @Override
    public String getMpWebRedirectUri(String appId, String redirectUri, String scope, String state) {
        try {
            String uri = new String(Base64Utils.decodeFromUrlSafeString(redirectUri));
            return Base64Utils.encodeToString(String.format("https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect", appId, uri, scope, state).getBytes(Charsets.UTF_8));
        } catch (Exception e) {
            logger.error("WxConfigServiceImpl getMpWebRedirectUri method error", e);
        }
        return null;
    }
}
