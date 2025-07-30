package mujina.idp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import mujina.api.IdpConfiguration;
import mujina.config.AuthnContextClassRefs;
import mujina.saml.SAMLAttribute;
import mujina.saml.SAMLPrincipal;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.NameIDType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Comparator.comparing;

@Controller
public class UserController {

    private final List<Map<String, String>> samlAttributes;
    private final AuthnContextClassRefs authnContextClassRefs;
    private final SAMLMessageHandler samlMessageHandler;
    private final IdpConfiguration idpConfiguration;

    @Autowired
    @SuppressWarnings("unchecked")
    public UserController(ObjectMapper objectMapper,
                          AuthnContextClassRefs authnContextClassRefs,
                          SAMLMessageHandler samlMessageHandler,
                          IdpConfiguration idpConfiguration,
                          @Value("${idp.saml_attributes_config_file}") String samlAttributesConfigFile) throws IOException {

        DefaultResourceLoader loader = new DefaultResourceLoader();
        this.samlAttributes = objectMapper.readValue(
                loader.getResource(samlAttributesConfigFile).getInputStream(), new TypeReference<>() {
                });
        this.samlAttributes.sort(comparing(m -> m.get("id")));
        this.authnContextClassRefs = authnContextClassRefs;
        this.samlMessageHandler = samlMessageHandler;
        this.idpConfiguration = idpConfiguration;
    }

    @GetMapping("/")
    public String index(Authentication authentication) {
        return authentication == null ? "index" : "redirect:/user.html";
    }

    @GetMapping("/user.html")
    public String user(Authentication authentication, ModelMap modelMap) {
        modelMap.addAttribute("user", authentication);
        return "user";
    }

    @GetMapping("/login")
    public String login(ModelMap modelMap) {
        modelMap.addAttribute("samlAttributes", samlAttributes);
        modelMap.addAttribute("authnContextClassRefs", authnContextClassRefs.getValues());
        return "login";
    }

    /**
     * IdP发起的SSO - 方案1：最小化改动实现
     * 硬编码SP信息，适合单一SP环境的快速实现
     */
    @PostMapping("/initiate-sso")
    public void initiateSso(Authentication authentication, 
                           HttpServletResponse response,
                           @RequestParam(value = "relayState", required = false) String relayState) throws Exception {
        
        if (authentication == null || !authentication.isAuthenticated()) {
            response.sendRedirect("/login");
            return;
        }
        
        // 硬编码SP信息 - 方案1的特点
        String spEntityId = "http://mock-sp"; // 默认SP实体ID
        String acsUrl = "http://localhost:9090/saml/SSO"; // 默认SP的ACS URL
        
        // 构建SAMLPrincipal用于IdP发起的SSO
        SAMLPrincipal principal = createSAMLPrincipal(authentication, spEntityId, acsUrl, relayState);
        
        // 发送SAML响应到SP
        samlMessageHandler.sendAuthnResponse(principal, AuthnContext.PASSWORD_AUTHN_CTX, response);
    }
    
    /**
     * 创建用于IdP发起SSO的SAMLPrincipal
     */
    private SAMLPrincipal createSAMLPrincipal(Authentication authentication, String spEntityId, String acsUrl, String relayState) {
        // 获取用户属性
        Map<String, String[]> parameterMap = (Map<String, String[]>) authentication.getDetails();
        if (parameterMap == null) {
            parameterMap = new HashMap<>();
        }
        
        // 构建用户属性列表
        List<SAMLAttribute> attributes = buildUserAttributes(authentication);
        
        // 获取NameID格式
        String nameIdFormat = attributes.stream()
                .filter(attr -> "urn:oasis:names:tc:SAML:1.1:nameid-format".equals(attr.getName()))
                .findFirst()
                .map(SAMLAttribute::getValue)
                .orElse(NameIDType.UNSPECIFIED);
        
        return new SAMLPrincipal(
            authentication.getName(),
            nameIdFormat,
            attributes,
            spEntityId,
            null, // IdP发起的SSO没有对应的AuthnRequest ID
            acsUrl,
            relayState
        );
    }
    
    /**
     * 构建用户属性
     */
    private List<SAMLAttribute> buildUserAttributes(Authentication authentication) {
        List<SAMLAttribute> attributes = new ArrayList<>();
        
        // 添加基本用户属性
        String username = authentication.getName();
        
        // 从IdP配置中获取默认属性
        Map<String, List<String>> defaultAttributes = idpConfiguration.getAttributes();
        
        for (Map.Entry<String, List<String>> entry : defaultAttributes.entrySet()) {
            String attributeName = entry.getKey();
            List<String> attributeValues = entry.getValue();
            
            // 替换占位符
            List<String> processedValues = attributeValues.stream()
                .map(value -> value.replace("${uid}", username))
                .collect(Collectors.toList());
            
            attributes.add(new SAMLAttribute(attributeName, processedValues));
        }
        
        // 注意：当前版本的IdpConfiguration不支持用户特定属性
        // 如需支持，可以扩展IdpConfiguration类添加getUserAttributes(String username)方法
        
        return attributes;
    }
}
