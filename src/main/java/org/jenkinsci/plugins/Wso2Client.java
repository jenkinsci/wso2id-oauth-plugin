package org.jenkinsci.plugins;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;
import org.apache.commons.httpclient.URIException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jfree.util.Log;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Created by jylzobei on 29/03/17.
 */
public class Wso2Client {

    public String post(String wso2WebUri, List<NameValuePair> parameters) throws IOException {
        HttpPost httpPost = new HttpPost(wso2WebUri);
        httpPost.setEntity(new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8));

        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost proxy = getProxy(httpPost);
        if (proxy != null) {
            RequestConfig config = RequestConfig.custom()
                    .setProxy(proxy)
                    .build();
            httpPost.setConfig(config);
        }
        org.apache.http.HttpResponse response = httpclient.execute(httpPost);

        HttpEntity entity = response.getEntity();

        String content = EntityUtils.toString(entity);

        // When HttpClient instance is no longer needed,
        // shut down the connection manager to ensure
        // immediate deallocation of all system resources
        httpclient.close();
        return content;
    }

    public Wso2User getUser(String wso2WebUri, String access_token) throws IOException {

        HttpGet httpGet = new HttpGet(wso2WebUri);
        httpGet.addHeader("Authorization", "Bearer "+access_token);
        CloseableHttpClient httpclient = HttpClients.createDefault();
        HttpHost proxy = getProxy(httpGet);
        if (proxy != null) {
            RequestConfig config = RequestConfig.custom()
                    .setProxy(proxy)
                    .build();
            httpGet.setConfig(config);
        }
        org.apache.http.HttpResponse response = httpclient.execute(httpGet);
        HttpEntity entity = response.getEntity();
        String content = EntityUtils.toString(entity);
        httpclient.close();
        return  extractUser(content);

    }

    private Wso2User extractUser(String content){
        ObjectMapper mapper = new ObjectMapper();
        String email = "";
        String username = "";
        String name = "";
        try {
            JsonNode node = mapper.readValue(content, JsonNode.class);
            JsonNode emailNode = node.get("email");
            JsonNode usernameNode = node.get("sub");
            JsonNode nameNode = node.get("preferred_username");
            if(emailNode != null){
                email = emailNode.asText();
            }
            if(usernameNode != null){
                username = usernameNode.asText();
            }
            if(nameNode != null){
                name = nameNode.asText();
            }

        } catch (IOException e) {
            Log.error(e.getMessage(), e);
        }
        return new Wso2User(username, name, email);
    }

    /**
     * Returns the proxy to be used when connecting to the given URI.
     */
    private HttpHost getProxy(HttpUriRequest method) throws URIException {
        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            return null; // defensive check
        }
        ProxyConfiguration proxy = jenkins.proxy;
        if (proxy == null)
        {
            return null; // defensive check
        }

        Proxy p = proxy.createProxy(method.getURI().getHost());
        switch (p.type()) {
            case DIRECT:
                return null; // no proxy
            case HTTP:
                InetSocketAddress sa = (InetSocketAddress) p.address();
                return new HttpHost(sa.getHostName(), sa.getPort());
            case SOCKS:
            default:
                return null; // not supported yet
        }
    }

}
