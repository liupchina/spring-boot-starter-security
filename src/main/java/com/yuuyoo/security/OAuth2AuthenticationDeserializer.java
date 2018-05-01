package com.yuuyoo.security;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.helpers.MessageFormatter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;

@Slf4j
public class OAuth2AuthenticationDeserializer extends JsonDeserializer<OAuth2Authentication> {


    private List<GrantedAuthority> getAuthorities(JsonNode node) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (node == null) return authorities;
        Iterator<JsonNode> iterator = node.elements();
        while (iterator.hasNext()) {
            JsonNode authItem = iterator.next();
            String authValue = getStringValue(authItem, "authority", null);
            authorities.add(new SimpleGrantedAuthority(authValue));
        }
        return authorities;
    }

    private Set<String> getStringSet(JsonNode node) {
        Set<String> result = new HashSet<>();
        if (node == null) return result;
        Iterator<JsonNode> iterator = node.elements();
        while (iterator.hasNext()) {
            JsonNode item = iterator.next();
            String value = item.textValue();
            result.add(value);
        }
        return result;
    }

    private Map<String, String> getStringMap(JsonNode node) {
        Map<String, String> result = new HashMap<>();
        if (node == null) return result;
        Iterator<String> iterator = node.fieldNames();
        while (iterator.hasNext()) {
            String key = iterator.next();
            if (key != null) {
                String value = node.get(key).textValue();
                result.put(key, value);
            }
        }
        return result;
    }

    private OAuth2Request getStoredRequest(JsonNode node) {
        if (node == null) return null;

        String clientId = getStringValue(node, "clientId", null);

        JsonNode scopeNode = node.has("scope") ? node.get("scope") : null;
        Set<String> scope = getStringSet(scopeNode);

        JsonNode requestParametersNode = node.has("requestParameters") ? node.get("requestParameters") : null;
        Map<String, String> requestParameters = getStringMap(requestParametersNode);

        JsonNode resourceIdsNode = node.has("resourceIds") ? node.get("resourceIds") : null;
        Set<String> resourceIds = getStringSet(resourceIdsNode);

        JsonNode authoritiesNode = node.has("authorities") ? node.get("authorities") : null;
        List<GrantedAuthority> storedAuthorities = getAuthorities(authoritiesNode);

        boolean approved = getBooleanValue(node, "approved", false);

        String redirectUri = getStringValue(node, "redirectUri", null);

        JsonNode responseTypesNode = node.has("responseTypes") ? node.get("responseTypes") : null;
        Set<String> responseTypes = getStringSet(responseTypesNode);

        OAuth2Request storedRequest = new OAuth2Request(requestParameters, clientId, storedAuthorities, approved, scope, resourceIds, redirectUri, responseTypes, null);

        JsonNode refreshTokenRequestNode = node.has("refreshTokenRequest") ? node.get("refreshTokenRequest") : null;
        boolean refresh = getBooleanValue(node, "refresh", false);
        if (refreshTokenRequestNode != null && refresh) {
            String grantType = getStringValue(refreshTokenRequestNode, "grantType", null);
            TokenRequest tokenRequest = new TokenRequest(requestParameters, clientId, scope, grantType);
            setFieldValueByReflect(storedRequest, "refresh", tokenRequest);
        }

        return storedRequest;
    }

    private void setFieldValueByReflect(Object object, String fieldName, Object value) {
        try {
            Field field = object.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(object, value);
        } catch (NoSuchFieldException e) {
            log.error("Unable to find the field " + fieldName, e);
            throw new RuntimeException(MessageFormatter.format("Unable to get the field '{}'", fieldName).getMessage());
        } catch (IllegalAccessException e) {
            log.error("Unable to set value to the field " + fieldName, e);
            throw new RuntimeException(MessageFormatter.format("Unable to set value to the field '{}'", fieldName).getMessage());
        }
    }

    private void setSuperFieldValueByReflect(Object object, String fieldName, Object value) {
        try {
            Field field = object.getClass().getSuperclass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(object, value);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e.getMessage());
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private String getStringValue(JsonNode node, String key, String defaultValue) {
        if (node == null || !node.has(key) || node.get(key) == null) return defaultValue;
        String value = node.get(key).textValue();
        if (value == null)
            return defaultValue;
        return value;
    }

    private Boolean getBooleanValue(JsonNode node, String key, Boolean defaultValue) {
        if (node == null || !node.has(key) || node.get(key) == null) return defaultValue;
        Boolean value = node.get(key).booleanValue();
        if (value == null)
            return defaultValue;
        return value;
    }

    private User getPrincipal(JsonNode node) {
        if (node == null) return null;
        String username = getStringValue(node, "username", null);
        boolean accountNonExpired = getBooleanValue(node, "accountNonExpired", true);
        boolean accountNonLocked = getBooleanValue(node, "accountNonLocked", true);
        boolean credentialsNonExpired = getBooleanValue(node, "credentialsNonExpired", true);
        boolean enabled = getBooleanValue(node, "enabled", true);

        JsonNode authoritiesNode = node.has("authorities") ? node.get("authorities") : null;
        List<GrantedAuthority> authorities = getAuthorities(authoritiesNode);

        User user = new User(username, "", enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        user.eraseCredentials();
        return user;

    }

    private Authentication getUserAuthentication(JsonNode node) {
        if (node == null) return null;

        JsonNode authoritiesNode = node.has("authorities") ? node.get("authorities") : null;
        List<GrantedAuthority> authorities = getAuthorities(authoritiesNode);

        boolean authenticated = getBooleanValue(node, "authenticated", false);

        JsonNode detailsNode = node.has("details") ? node.get("details") : null;
        Map<String, String> details = getStringMap(detailsNode);

        JsonNode principalNode = node.has("principal") ? node.get("principal") : null;
        User principal = getPrincipal(principalNode);

        UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
        setSuperFieldValueByReflect(userAuthentication, "authenticated", authenticated);
        userAuthentication.setDetails(details);
        return userAuthentication;
    }


    @Override
    public OAuth2Authentication deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
        ObjectCodec oc = jsonParser.getCodec();
        JsonNode node = oc.readTree(jsonParser);

        //Collection<GrantedAuthority> authorities
        JsonNode authoritiesNode = node.has("authorities") ? node.get("authorities") : null;
        List<GrantedAuthority> authorities = getAuthorities(authoritiesNode);

        //Object details没有内容

        //boolean authenticated
        boolean authenticated = getBooleanValue(node, "authenticated", false);

        //OAuth2Request storedRequest
        JsonNode storedRequestNode = node.has("oauth2Request") ? node.get("oauth2Request") : null;
        OAuth2Request storedRequest = getStoredRequest(storedRequestNode);

        //Authentication userAuthentication
        JsonNode userAuthenticationNode = node.has("userAuthentication") ? node.get("userAuthentication") : null;
        Authentication userAuthentication = getUserAuthentication(userAuthenticationNode);


        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(storedRequest, userAuthentication);
        oAuth2Authentication.setAuthenticated(authenticated);
        return oAuth2Authentication;
    }
}