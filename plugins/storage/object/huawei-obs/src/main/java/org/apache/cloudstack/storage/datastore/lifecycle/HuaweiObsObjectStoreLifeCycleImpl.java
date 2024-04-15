package org.apache.cloudstack.storage.datastore.lifecycle;

import com.cloud.agent.api.StoragePoolInfo;
import com.cloud.hypervisor.Hypervisor.HypervisorType;
import com.cloud.utils.exception.CloudRuntimeException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.apache.cloudstack.engine.subsystem.api.storage.ClusterScope;
import org.apache.cloudstack.engine.subsystem.api.storage.DataStore;
import org.apache.cloudstack.engine.subsystem.api.storage.HostScope;
import org.apache.cloudstack.engine.subsystem.api.storage.ZoneScope;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreVO;
import org.apache.cloudstack.storage.object.datastore.ObjectStoreHelper;
import org.apache.cloudstack.storage.object.datastore.ObjectStoreProviderManager;
import org.apache.cloudstack.storage.object.store.lifecycle.ObjectStoreLifeCycle;
import org.apache.log4j.Logger;

public class HuaweiObsObjectStoreLifeCycleImpl implements ObjectStoreLifeCycle {

    protected final Logger logger = Logger.getLogger(getClass());

    @Inject
    ObjectStoreHelper objectStoreHelper;
    @Inject
    ObjectStoreProviderManager objectStoreMgr;

    public HuaweiObsObjectStoreLifeCycleImpl() {
    }

    @SuppressWarnings("unchecked")
    @Override
    public DataStore initialize(Map<String, Object> dsInfos) {
        String url = (String) dsInfos.get("url");
        String name = (String) dsInfos.get("name");
        String providerName = (String) dsInfos.get("providerName");
        Map<String, String> details = (Map<String, String>) dsInfos.get("details");
        if (details == null) {
            throw new CloudRuntimeException("Huawei OBS credentials are missing");
        }
        String accessKey = details.get("accesskey");
        String secretKey = details.get("secretkey");

        Map<String, Object> objectStoreParameters = new HashMap();
        objectStoreParameters.put("name", name);
        objectStoreParameters.put("url", url);

        objectStoreParameters.put("providerName", providerName);
        objectStoreParameters.put("accesskey", accessKey);
        objectStoreParameters.put("secretkey", secretKey);

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("GET").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/");
            String SIGNATURE_METHOD = "HmacSHA1";
            Mac mac = Mac.getInstance(SIGNATURE_METHOD);
            mac.init(new SecretKeySpec(secretKey.getBytes("UTF-8"), SIGNATURE_METHOD));
            String signature = Base64.getEncoder().encodeToString(mac.doFinal(data.toString().getBytes("UTF-8")));
            HttpRequest request = HttpRequest.newBuilder(new URI(url))
                    .GET()
                    .setHeader("Authorization", "OBS " + accessKey + ":" + signature)
                    .setHeader("Date", timestamp)
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(10))
                    .build();
            TrustManager TRUST_ANY_CERTIFICATE = new X509ExtendedTrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    // do nothing
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                    // do nothing
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                    // do nothing
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    // do nothing
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                    // do nothing
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                    // do nothing
                }
            };
            TrustManager[] TRUST_ANY_CERTIFICATES = new TrustManager[]{TRUST_ANY_CERTIFICATE};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, TRUST_ANY_CERTIFICATES, new SecureRandom());
            HttpClient httpClient = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
            httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.debug("Successfully connected to Huawei OBS EndPoint: " + url);
        } catch (Exception ex) {
            logger.debug("Error while initializing Huawei OBS Object Store: ", ex);
            throw new RuntimeException("Error while initializing Huawei OBS Object Store. Invalid credentials or endpoint URL", ex);
        }

        ObjectStoreVO objectStore = objectStoreHelper.createObjectStore(objectStoreParameters, details);
        return objectStoreMgr.getObjectStore(objectStore.getId());
    }

    @Override
    public boolean attachCluster(DataStore store, ClusterScope scope) {
        return false;
    }

    @Override
    public boolean attachHost(DataStore store, HostScope scope, StoragePoolInfo existingInfo) {
        return false;
    }

    @Override
    public boolean attachZone(DataStore dataStore, ZoneScope scope, HypervisorType hypervisorType) {
        return false;
    }

    @Override
    public boolean maintain(DataStore store) {
        return false;
    }

    @Override
    public boolean cancelMaintain(DataStore store) {
        return false;
    }

    @Override
    public boolean deleteDataStore(DataStore store) {
        return false;
    }

    /* (non-Javadoc)
     * @see org.apache.cloudstack.engine.subsystem.api.storage.DataStoreLifeCycle#migrateToObjectStore(org.apache.cloudstack.engine.subsystem.api.storage.DataStore)
     */
    @Override
    public boolean migrateToObjectStore(DataStore store) {
        return false;
    }

}
