package com.yuuyoo.security;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import java.io.IOException;
import java.util.Date;

@Slf4j
public class OAuth2RefreshTokenDeserializer extends JsonDeserializer<OAuth2RefreshToken> {


    private String getStringValue(JsonNode node, String key, String defaultValue) {
        if (node == null || !node.has(key) || node.get(key) == null) return defaultValue;
        String value = node.get(key).textValue();
        if (value == null)
            return defaultValue;
        return value;
    }

    private Long getLongValue(JsonNode node, String key, Long defaultValue) {
        if (node == null || !node.has(key) || node.get(key) == null) return defaultValue;
        Long value = node.get(key).longValue();
        if (value == null)
            return defaultValue;
        return value;
    }



    @Override
    public OAuth2RefreshToken deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        ObjectCodec oc = jsonParser.getCodec();
        JsonNode node = oc.readTree(jsonParser);

        String value = getStringValue(node, "value", null);
        Long expiration = getLongValue(node, "expiration", null);
        if(expiration == null) {
            return new DefaultOAuth2RefreshToken(value);
        } else {
            return new DefaultExpiringOAuth2RefreshToken(value, new Date(expiration));
        }
    }
}