package cn.com.simpleuse.auth.controller;

import cn.com.simpleuse.auth.service.WxConfigService;
import com.google.common.collect.Maps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MpWebAuthController {

    private static final Logger logger = LoggerFactory.getLogger(MpWebAuthController.class);
    @Autowired
    private WxConfigService wxConfigService;

    @RequestMapping(path = "mp_auth_uri")
    public ResponseEntity<Map<String, String>> auth(
            @RequestParam(required = true) String redirectUri,
            @RequestParam(required = false, defaultValue = "snsapi_base") String scope,
            @RequestParam(required = false, defaultValue = "") String state) {
        Map<String, String> result = Maps.newLinkedHashMap();
        try {
            logger.info("MpWebAuthController.auth,redirectUri:{},scope:{},state:{}",redirectUri,scope,state);
            // scope
            //     snsapi_base,snsapi_userinfo
            result.put("code", String.valueOf(HttpStatus.OK.value()));
            result.put("msg", "GET MP WEB AUTH REDIRECTURI SUCCESS");
            String link = wxConfigService.getMpWebRedirectUri(wxConfigService.getAppId(), redirectUri, scope, state);
            result.put("data", link);

            return  ResponseEntity.ok().body(result);
        } catch (Exception e) {
            logger.error("GET MP WEB AUTH REDIRECTURI FAILED", e);
            result.put("code", String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()));
            result.put("msg", "GET MP WEB AUTH REDIRECTURI FAILED");
            result.put("data", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }


    @RequestMapping(path = "mp_auth_user_openid")
    public ResponseEntity<Map<String, String>> auth(
            @RequestParam(required = true) String code,
            @RequestParam(required = false, defaultValue = "") String state) {
        Map<String, String> result = Maps.newLinkedHashMap();
        try {
            result.put("code", String.valueOf(HttpStatus.OK.value()));
            result.put("msg", "GET MP USER OPENID SUCCESS");
            result.put("data", wxConfigService.getMpOpenId(code,state));
            return  ResponseEntity.ok().body(result);
        } catch (Exception e) {
            logger.error("GET MP USER OPENID FAILED", e);
            result.put("code", String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()));
            result.put("msg", "GET MP USER OPENID FAILED");
            result.put("data", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
        }
    }

}
