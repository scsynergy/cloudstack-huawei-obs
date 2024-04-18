package org.apache.cloudstack.storage.datastore.driver;

import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.BucketPolicy;
import com.amazonaws.services.s3.model.CanonicalGrantee;
import com.amazonaws.services.s3.model.Grant;
import com.amazonaws.services.s3.model.Grantee;
import com.amazonaws.services.s3.model.Owner;
import com.amazonaws.services.s3.model.Permission;
import com.cloud.agent.api.to.DataStoreTO;
import com.cloud.storage.BucketVO;
import com.cloud.storage.dao.BucketDao;
import com.cloud.user.Account;
import com.cloud.user.AccountDetailsDao;
import com.cloud.user.dao.AccountDao;
import com.cloud.utils.exception.CloudRuntimeException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.apache.cloudstack.engine.subsystem.api.storage.DataStore;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreDao;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreDetailsDao;
import org.apache.cloudstack.storage.object.BaseObjectStoreDriverImpl;
import org.apache.cloudstack.storage.object.Bucket;
import org.apache.cloudstack.storage.object.BucketObject;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreVO;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.XML;

public class HuaweiObsObjectStoreDriverImpl extends BaseObjectStoreDriverImpl {

    @Inject
    AccountDao _accountDao;
    @Inject
    AccountDetailsDao _accountDetailsDao;
    @Inject
    ObjectStoreDao _storeDao;
    @Inject
    BucketDao _bucketDao;
    @Inject
    ObjectStoreDetailsDao _storeDetailsDao;

    private static final String OBJECT_STORE_ACCESS_KEY = "accesskey";
    private static final String OBJECT_STORE_SECRET_KEY = "secretkey";
    private static final String ACCOUNT_ACCESS_KEY = "huawei-obs-accesskey";
    private static final String ACCOUNT_SECRET_KEY = "huawei-obs-secretkey";
    private static final String POE_SIGNATURE_METHOD = "HmacSHA256";
    private static final String SIGNATURE_VERSION = "4";
    private static final String CONTENT_MD5 = "Content-MD5";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String UTF_8 = "UTF-8";
    private static HttpClient httpClient;
    private static final TrustManager TRUST_ANY_CERTIFICATE = new X509ExtendedTrustManager() {
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
    private static final TrustManager[] TRUST_ANY_CERTIFICATES = new TrustManager[]{TRUST_ANY_CERTIFICATE};
    protected final Logger logger = Logger.getLogger(HuaweiObsObjectStoreDriverImpl.class.getName());

    @Override
    public DataStoreTO getStoreTO(DataStore store) {
        return null;
    }

    @Override
    public Bucket createBucket(Bucket bucket, boolean objectLock) {
        long accountId = bucket.getAccountId();
        long storeId = bucket.getObjectStoreId();
        Account account = _accountDao.findById(accountId);
        String userId = account.getUuid(); // this is the Cloudstack user that pressed the button of the UI
        String userName = account.getAccountName(); // this is the Cloudstack user that pressed the button of the UI
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket
        String bucketName = bucket.getName();

        if ((_accountDetailsDao.findDetail(accountId, ACCOUNT_ACCESS_KEY) == null) || (_accountDetailsDao.findDetail(accountId, ACCOUNT_SECRET_KEY) == null)) {
            throw new CloudRuntimeException("Bucket access credentials unavailable for account: " + account.getAccountName());
        }

        try {
            URI createBucketUri = new URI(endpoint);
            if (headBucket(bucketName, createBucketUri, accountAccessKey, accountSecretKey)) {
                throw new CloudRuntimeException("A bucket with the name " + bucketName + " already exists");
            }

            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/");
            StringBuilder requestString = new StringBuilder()
                    .append(createBucketUri.getScheme()).append("://").append(bucketName).append(".").append(createBucketUri.getHost());
            createBucketUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(createBucketUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("createBucket === " + response.statusCode());
            if (response.statusCode() == 200) {
                URI poeEndpointUri = new URI("https://poe-obs.scsynergy.net:9443/poe/rest");
                String userBucketPolicy = createUserBucketPolicy(bucketName, userName, poeEndpointUri, accountAccessKey, accountSecretKey);
                setBucketPolicy(bucketName, userBucketPolicy, storeId);
                BucketVO bucketVO = _bucketDao.findById(bucket.getId());
                String userAccessKey = _accountDetailsDao.findDetail(accountId, ACCOUNT_ACCESS_KEY).getValue();
                String userSecretKey = _accountDetailsDao.findDetail(accountId, ACCOUNT_SECRET_KEY).getValue();
                // Cloudstack can only handle path mode (https://fqdn:port/bucketName) but neither domain mode (https://bucketName.fqdn:port) nor mixed mode (https://bucketName.fqdn:port/bucketName)
                bucketVO.setBucketURL(endpoint + "/" + bucketName);
                bucketVO.setAccessKey(userAccessKey);
                bucketVO.setSecretKey(userSecretKey);
                _bucketDao.update(bucket.getId(), bucketVO);
                cors(bucketName, createBucketUri, accountAccessKey, accountSecretKey);
                return bucketVO;
            }
            System.err.println(response.body());
            System.err.println("createBucket ===");
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
        return bucket;
    }

    protected boolean headBucket(String bucketName, URI endpoint, String accountAccessKey, String accountSecretKey) throws URISyntaxException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, KeyManagementException, IOException, InterruptedException {
        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("HEAD").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/");
            StringBuilder requestString = new StringBuilder()
                    .append(endpoint.getScheme()).append("://").append(bucketName).append(".").append(endpoint.getHost());
            URI headBucketUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(headBucketUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("headBucket === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("headBucket ===");
            }
            return response.statusCode() == 200;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return true;
    }

    protected void cors(String bucketName, URI endpoint, String accountAccessKey, String accountSecretKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, URISyntaxException, InvalidKeyException, KeyManagementException, IOException, InterruptedException {
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
        StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                .append("<CORSConfiguration>\n")
                .append("  <CORSRule>\n")
                .append("    <AllowedMethod>POST</AllowedMethod>\n")
                .append("    <AllowedMethod>GET</AllowedMethod>\n")
                .append("    <AllowedMethod>HEAD</AllowedMethod>\n")
                .append("    <AllowedMethod>PUT</AllowedMethod>\n")
                .append("    <AllowedMethod>DELETE</AllowedMethod>\n")
                .append("    <AllowedOrigin>*</AllowedOrigin>\n")
                .append("    <MaxAgeSeconds>86400</MaxAgeSeconds>\n")
                .append("    <AllowedHeader>*</AllowedHeader>\n")
                .append("    <ExposeHeader>Access-Control-Allow-Origin</ExposeHeader>\n")
                .append("    <ExposeHeader>Vary</ExposeHeader>\n")
                .append("  </CORSRule>\n")
                .append("</CORSConfiguration>");
        String body = bodyBuilder.toString();
        byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(UTF_8));
        String base64 = Base64.getEncoder().encodeToString(md5);
        StringBuilder data = new StringBuilder()
                .append("PUT").append("\n")
                .append(base64).append("\n")
                .append("application/xml").append("\n")
                .append(timestamp).append("\n")
                .append("/").append(bucketName).append("/")
                .append('?').append("cors");
        endpoint = new URI(endpoint.toASCIIString().concat("?cors"));
        HttpRequest request = authorizationHeaders(endpoint, timestamp, accountAccessKey, accountSecretKey, data)
                .PUT(HttpRequest.BodyPublishers.ofString(body))
                .setHeader(CONTENT_MD5, base64)
                .setHeader(CONTENT_TYPE, "application/xml")
                .build();
        HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        System.err.println("cors === " + response.statusCode());
        if (response.statusCode() != 200) {
            System.err.println(response.body());
            System.err.println("cors ===");
        }
    }

    @Override
    public List<Bucket> listBuckets(long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        List<Bucket> bucketsList = new ArrayList<>();
        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("GET").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/");
            URI listBucketsUri = new URI(endpoint);
            HttpRequest request = authorizationHeaders(listBucketsUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .GET()
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("listBuckets === " + response.statusCode());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                JSONArray buckets = jsonXml
                        .getJSONObject("ListAllMyBucketsResult")
                        .getJSONObject("Buckets")
                        .getJSONArray("Bucket");
                Iterator iter = buckets.iterator();
                while (iter.hasNext()) {
                    JSONObject object = (JSONObject) iter.next();
                    Bucket bucket = new BucketObject();
                    bucket.setName(object.getString("Name"));
                    bucketsList.add(bucket);
                }
            }
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("listBuckets ===");
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return bucketsList;
    }

    @Override
    public boolean deleteBucket(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            URI deleteBucketUri = new URI(endpoint);
            if (!headBucket(bucketName, deleteBucketUri, accountAccessKey, accountSecretKey)) {
                throw new CloudRuntimeException("Bucket does not exist: " + bucketName);
            }

            Long[] storageInfo = getStorageInfo(bucketName, deleteBucketUri, accountAccessKey, accountSecretKey);
            if (storageInfo[0] > 0) {
                throw new CloudRuntimeException("Bucket " + bucketName + " cannot be deleted because it is not empty");
            }

            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("DELETE").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/");
            StringBuilder requestString = new StringBuilder()
                    .append(deleteBucketUri.getScheme()).append("://").append(bucketName).append(".").append(deleteBucketUri.getHost());
            deleteBucketUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(deleteBucketUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .DELETE()
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("deleteBucket === " + response.statusCode());
            if (response.statusCode() != 204) {
                System.err.println(response.body());
                System.err.println("deleteBucket ===");
            }
            return response.statusCode() == 204;
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    protected Long[] getStorageInfo(String bucketName, URI endpoint, String accountAccessKey, String accountSecretKey) throws URISyntaxException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, KeyManagementException, IOException, InterruptedException {
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
        StringBuilder data = new StringBuilder()
                .append("GET").append("\n")
                .append("\n")
                .append("\n")
                .append(timestamp).append("\n")
                .append("/").append(bucketName).append("/")
                .append('?').append("storageinfo");
        StringBuilder requestString = new StringBuilder()
                .append(endpoint.getScheme()).append("://").append(bucketName).append(".").append(endpoint.getHost())
                .append('?').append("storageinfo");
        URI storageinfoUri = new URI(requestString.toString());
        HttpRequest request = authorizationHeaders(storageinfoUri, timestamp, accountAccessKey, accountSecretKey, data)
                .GET()
                .build();
        HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        System.err.println("getStorageInfo === " + response.statusCode());
        if (response.statusCode() == 200) {
            JSONObject jsonXml = XML.toJSONObject(response.body());
            Long objectNumber = jsonXml
                    .getJSONObject("GetBucketStorageInfoResult")
                    .getLong("ObjectNumber");
            Long size = jsonXml
                    .getJSONObject("GetBucketStorageInfoResult")
                    .getLong("Size");
            return new Long[]{objectNumber, size};
        }
        System.err.println(response.body());
        System.err.println("getStorageInfo ===");
        return new Long[]{-1L, -1L};
    }

    @Override
    public AccessControlList getBucketAcl(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            URI poeEndpointUri = new URI("https://poe-obs.scsynergy.net:9443/poe/rest");
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("GET").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("acl");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("acl");
            URI aclUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(aclUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .GET()
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("getBucketAcl === " + response.statusCode());
            AccessControlList accessControlList = new AccessControlList();
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                String ownerId = jsonXml
                        .getJSONObject("AccessControlPolicy")
                        .getJSONObject("Owner")
                        .getString("ID");
                String self = getUser(null, poeEndpointUri, accountAccessKey, accountSecretKey).getString("UserName");
                JSONObject grant = jsonXml
                        .getJSONObject("AccessControlPolicy")
                        .getJSONObject("AccessControlList")
                        .getJSONObject("Grant");
                Grantee grantee = new CanonicalGrantee(grant.getJSONObject("Grantee").getString("ID"));
                Permission permission = Permission.parsePermission(grant.getString("Permission"));
                accessControlList.setOwner(new Owner(ownerId, self));
                accessControlList.grantPermission(grantee, permission);
            }
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("getBucketAcl ===");
            }
            return accessControlList;
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    private JSONObject getUser(String userName, URI poeEndpoint, String poeAccessKeyId, String poeAccessKeySecret) throws URISyntaxException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, KeyManagementException, IOException, InterruptedException {
        URI getUserUri = new URI(userRequestString("GetUser", poeEndpoint, poeAccessKeyId, poeAccessKeySecret, null, userName, null, null));
        HttpRequest request = HttpRequest.newBuilder(getUserUri)
                .GET()
                .version(HttpClient.Version.HTTP_2)
                .timeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        System.err.println("getSelf === " + response.statusCode());
        if (response.statusCode() == 200) {
            return XML.toJSONObject(response.body())
                    .getJSONObject("GetUserResponse")
                    .getJSONObject("GetUserResult")
                    .getJSONObject("User");
        }
        if (response.statusCode() != 200) {
            System.err.println(response.body());
            System.err.println("getSelf ===");
        }
        return new JSONObject().append("UserName", "unkown because of error").append("Arn", "unkown because of error");
    }

    @Override
    public void setBucketAcl(String bucketName, AccessControlList accessControlList, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                    .append("<AccessControlPolicy>\n")
                    .append("  <Owner>\n")
                    .append("    <ID>").append(accessControlList.getOwner().getId()).append("</ID>\n")
                    .append("  </Owner>\n")
                    .append("  <AccessControlList>\n");
            for (Grant grant : accessControlList.getGrantsAsList()) {
                bodyBuilder.append("    <Grant>\n");
                bodyBuilder.append("      <Grantee>\n");
                bodyBuilder.append("        <ID>").append(grant.getGrantee().getIdentifier()).append("</ID>\n");
                bodyBuilder.append("      </Grantee>\n");
                bodyBuilder.append("      <Permission>").append(grant.getPermission().toString()).append("</Permission>\n");
                bodyBuilder.append("    </Grant>\n");
            }
            bodyBuilder.append("  </AccessControlList>\n")
                    .append("</AccessControlPolicy>");
            String body = bodyBuilder.toString();
            byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(UTF_8));
            String base64 = Base64.getEncoder().encodeToString(md5);
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append(base64).append("\n")
                    .append("application/xml").append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("acl");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("acl");
            URI aclUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(aclUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .setHeader(CONTENT_MD5, base64)
                    .setHeader(CONTENT_TYPE, "application/xml")
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("setBucketAcl === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("setBucketAcl ===");
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    private String createUserBucketPolicy(String bucketname, String userName, URI poeEndpoint, String accountAccessKey, String accountSecretKey) throws URISyntaxException, InvalidKeyException, NoSuchAlgorithmException, KeyManagementException, IOException, UnsupportedEncodingException, InterruptedException {
        JSONObject specificUser = getUser(userName, poeEndpoint, accountAccessKey, accountSecretKey);
        String arn = specificUser.getString("Arn")
                .replace("iam:", "domain/")
                .replace(":", ":user/");
        String id = "Policy" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
        StringBuilder specificUserPolicy = new StringBuilder();
        specificUserPolicy.append("{\n");
        specificUserPolicy.append("   \"Version\": \"2008-10-17\",\n");
        specificUserPolicy.append("   \"Id\": \"").append(id).append("\",\n");
        specificUserPolicy.append("   \"Statement\": [\n");
        specificUserPolicy.append("      {\n");
        specificUserPolicy.append("         \"Sid\": \"specificUserReadWritePolicyStatementId\",\n");
        specificUserPolicy.append("         \"Effect\": \"Allow\",\n");
        specificUserPolicy.append("         \"Principal\": {\n");
        specificUserPolicy.append("            \"ID\": [\n");
        specificUserPolicy.append("               \"").append(arn).append("\"\n");
        specificUserPolicy.append("            ]\n");
        specificUserPolicy.append("         },\n");
        specificUserPolicy.append("         \"Action\": [\n");
        specificUserPolicy.append("            \"GetObject\",\n");
        specificUserPolicy.append("            \"PutObject\",\n");
        specificUserPolicy.append("            \"GetObjectVersion\",\n");
        specificUserPolicy.append("            \"DeleteObjectVersion\",\n");
        specificUserPolicy.append("            \"DeleteObject\",\n");
        specificUserPolicy.append("            \"ListMultipartUploadParts\",\n");
        specificUserPolicy.append("            \"GetObjectAcl\",\n");
        specificUserPolicy.append("            \"GetObjectVersionAcl\",\n");
        specificUserPolicy.append("            \"PutObjectAcl\",\n");
        specificUserPolicy.append("            \"PutObjectVersionAcl\",\n");
        specificUserPolicy.append("            \"AbortMultipartUpload\"\n");
        specificUserPolicy.append("         ],\n");
        specificUserPolicy.append("         \"Resource\": [\n");
        specificUserPolicy.append("            \"").append(bucketname).append("/*\"\n");
        specificUserPolicy.append("         ]\n");
        specificUserPolicy.append("      },\n");
        specificUserPolicy.append("      {\n");
        specificUserPolicy.append("         \"Sid\": \"specificUserListBucketPolicyStatementId\",\n");
        specificUserPolicy.append("         \"Effect\": \"Allow\",\n");
        specificUserPolicy.append("         \"Principal\": {\n");
        specificUserPolicy.append("            \"ID\": [\n");
        specificUserPolicy.append("               \"").append(arn).append("\"\n");
        specificUserPolicy.append("            ]\n");
        specificUserPolicy.append("         },\n");
        specificUserPolicy.append("         \"Action\": [\n");
        specificUserPolicy.append("            \"ListBucket\",\n");
        specificUserPolicy.append("            \"ListBucketVersions\",\n");
        specificUserPolicy.append("            \"ListBucketMultipartUploads\"\n");
        specificUserPolicy.append("         ],\n");
        specificUserPolicy.append("         \"Resource\": [\n");
        specificUserPolicy.append("            \"").append(bucketname).append("\"\n");
        specificUserPolicy.append("         ]\n");
        specificUserPolicy.append("      }\n");
        specificUserPolicy.append("   ]\n");
        specificUserPolicy.append("}");
        return specificUserPolicy.toString();
    }

    /**
     * When a bucket is created as "private" via the Huawei UI it simply does
     * not have a policy. Trying to read or delete the bucket policy of a
     * "private" bucket results in "404 - The bucket policy does not exist".
     * Huawei's UI has three default policies to choose from: "private", "public
     * read-only" and "public read-write". Since the Cloudstack UI only offers
     * "private" and "public" in the dropdown I chose to map "public" to
     * "public-read-write" and "private" to "public read-only" and to map the
     * default empty dropdown selection to Huawei's "private" policy. Maybe in
     * the future we can have the UI adapt the items in the dropdown depending
     * on what provider is selected?
     *
     * @param bucketName
     * @param policy
     * @param storeId
     */
    @Override
    public void setBucketPolicy(String bucketName, String policy, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        if (policy == null) {
            return;
        } else if (policy.equalsIgnoreCase("private")) {
            String id = "Policy" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            StringBuilder publicRead = new StringBuilder();
            publicRead.append("{\n");
            publicRead.append("   \"Version\": \"2008-10-17\",\n");
            publicRead.append("   \"Id\": \"").append(id).append("\",\n");
            publicRead.append("   \"Statement\": [\n");
            publicRead.append("      {\n");
            publicRead.append("         \"Sid\": \"publicReadOnlyPolicyStatementId\",\n");
            publicRead.append("         \"Effect\": \"Allow\",\n");
            publicRead.append("         \"Principal\": {\n");
            publicRead.append("            \"ID\": [\n");
            publicRead.append("               \"*\"\n");
            publicRead.append("            ]\n");
            publicRead.append("         },\n");
            publicRead.append("         \"Action\": [\n");
            publicRead.append("            \"GetObject\",\n");
            publicRead.append("            \"GetObjectVersion\",\n");
            publicRead.append("            \"ListMultipartUploadParts\",\n");
            publicRead.append("            \"GetObjectAcl\",\n");
            publicRead.append("            \"GetObjectVersionAcl\"\n");
            publicRead.append("         ],\n");
            publicRead.append("         \"Resource\": [\n");
            publicRead.append("            \"").append(bucketName).append("/*\"\n");
            publicRead.append("         ]\n");
            publicRead.append("      },\n");
            publicRead.append("      {\n");
            publicRead.append("         \"Sid\": \"publicHeadBucketPolicyStatementId\",\n");
            publicRead.append("         \"Effect\": \"Allow\",\n");
            publicRead.append("         \"Principal\": {\n");
            publicRead.append("            \"ID\": [\n");
            publicRead.append("               \"*\"\n");
            publicRead.append("            ]\n");
            publicRead.append("         },\n");
            publicRead.append("         \"Action\": [\n");
            publicRead.append("            \"HeadBucket\",\n");
            publicRead.append("            \"ListBucket\"\n");
            publicRead.append("         ],\n");
            publicRead.append("         \"Resource\": [\n");
            publicRead.append("            \"").append(bucketName).append("\"\n");
            publicRead.append("         ]\n");
            publicRead.append("      }\n");
            publicRead.append("   ]\n");
            publicRead.append("}");
            policy = publicRead.toString();
        } else if (policy.equalsIgnoreCase("public")) {
            String id = "Policy" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
            StringBuilder publicWrite = new StringBuilder();
            publicWrite.append("{\n");
            publicWrite.append("   \"Version\": \"2008-10-17\",\n");
            publicWrite.append("   \"Id\": \"").append(id).append("\",\n");
            publicWrite.append("   \"Statement\": [\n");
            publicWrite.append("      {\n");
            publicWrite.append("         \"Sid\": \"publicReadWritePolicyStatementId\",\n");
            publicWrite.append("         \"Effect\": \"Allow\",\n");
            publicWrite.append("         \"Principal\": {\n");
            publicWrite.append("            \"ID\": [\n");
            publicWrite.append("               \"*\"\n");
            publicWrite.append("            ]\n");
            publicWrite.append("         },\n");
            publicWrite.append("         \"Action\": [\n");
            publicWrite.append("            \"GetObject\",\n");
            publicWrite.append("            \"PutObject\",\n");
            publicWrite.append("            \"GetObjectVersion\",\n");
            publicWrite.append("            \"DeleteObjectVersion\",\n");
            publicWrite.append("            \"DeleteObject\",\n");
            publicWrite.append("            \"ListMultipartUploadParts\",\n");
            publicWrite.append("            \"GetObjectAcl\",\n");
            publicWrite.append("            \"GetObjectVersionAcl\",\n");
            publicWrite.append("            \"PutObjectAcl\",\n");
            publicWrite.append("            \"PutObjectVersionAcl\",\n");
            publicWrite.append("            \"AbortMultipartUpload\"\n");
            publicWrite.append("         ],\n");
            publicWrite.append("         \"Resource\": [\n");
            publicWrite.append("            \"").append(bucketName).append("/*\"\n");
            publicWrite.append("         ]\n");
            publicWrite.append("      },\n");
            publicWrite.append("      {\n");
            publicWrite.append("         \"Sid\": \"publicHeadBucketPolicyStatementId\",\n");
            publicWrite.append("         \"Effect\": \"Allow\",\n");
            publicWrite.append("         \"Principal\": {\n");
            publicWrite.append("            \"ID\": [\n");
            publicWrite.append("               \"*\"\n");
            publicWrite.append("            ]\n");
            publicWrite.append("         },\n");
            publicWrite.append("         \"Action\": [\n");
            publicWrite.append("            \"HeadBucket\",\n");
            publicWrite.append("            \"ListBucket\"\n");
            publicWrite.append("         ],\n");
            publicWrite.append("         \"Resource\": [\n");
            publicWrite.append("            \"").append(bucketName).append("\"\n");
            publicWrite.append("         ]\n");
            publicWrite.append("      }\n");
            publicWrite.append("   ]\n");
            publicWrite.append("}");
            policy = publicWrite.toString();
        }
        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            byte[] md5 = MessageDigest.getInstance("MD5").digest(policy.getBytes(UTF_8));
            String base64 = Base64.getEncoder().encodeToString(md5);
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append(base64).append("\n")
                    .append("application/xml").append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("policy");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("policy");
            URI policyUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(policyUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.ofString(policy))
                    .setHeader(CONTENT_MD5, base64)
                    .setHeader(CONTENT_TYPE, "application/xml")
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("setBucketPolicy === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("setBucketPolicy ===");
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    /**
     * When a bucket is created as "private" via the Huawei UI it simply does
     * not have a policy. Trying to read or delete the bucket policy of a
     * "private" bucket results in "404 - The bucket policy does not exist".
     *
     * @param bucketName
     * @param storeId
     * @return
     */
    @Override
    public BucketPolicy getBucketPolicy(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("GET").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("policy");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("policy");
            URI policyUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(policyUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .GET()
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("getBucketPolicy === " + response.statusCode());
            BucketPolicy bucketPolicy = new BucketPolicy();
            if (response.statusCode() == 200) {
                bucketPolicy.setPolicyText(response.body());
            }
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("getBucketPolicy ===");
            }
            return bucketPolicy;
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    /**
     * When a bucket is created as "private" via the Huawei UI it simply does
     * not have a policy. Trying to read or delete the bucket policy of a
     * "private" bucket results in "404 - The bucket policy does not exist".
     *
     * @param bucketName
     * @param storeId
     */
    @Override
    public void deleteBucketPolicy(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("DELETE").append("\n")
                    .append("\n")
                    .append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("policy");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("policy");
            URI policyUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(policyUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .DELETE()
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("deleteBucketPolicy === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("deleteBucketPolicy ===");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public boolean setBucketEncryption(String bucketName, long storeId) {
        return false; // not yet implemented
    }

    @Override
    public boolean deleteBucketEncryption(String bucketName, long storeId) {
        return false; // not yet implemented
    }

    @Override
    public boolean setBucketVersioning(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                    .append("<VersioningConfiguration>\n")
                    .append("  <Status>Enabled</Status>\n")
                    .append("</VersioningConfiguration>");
            String body = bodyBuilder.toString();
            byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(UTF_8));
            String base64 = Base64.getEncoder().encodeToString(md5);
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append(base64).append("\n")
                    .append("application/xml").append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("versioning");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("versioning");
            URI versioningUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(versioningUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .setHeader(CONTENT_MD5, base64)
                    .setHeader(CONTENT_TYPE, "application/xml")
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("setBucketVersioning === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("setBucketVersioning ===");
            }
            return response.statusCode() == 200;
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public boolean deleteBucketVersioning(String bucketName, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                    .append("<VersioningConfiguration>\n")
                    .append("  <Status>Suspended</Status>\n")
                    .append("</VersioningConfiguration>");
            String body = bodyBuilder.toString();
            byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(UTF_8));
            String base64 = Base64.getEncoder().encodeToString(md5);
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append(base64).append("\n")
                    .append("application/xml").append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("versioning");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("versioning");
            URI versioningUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(versioningUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .setHeader(CONTENT_MD5, base64)
                    .setHeader(CONTENT_TYPE, "application/xml")
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("setBucketVersioning === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("setBucketVersioning ===");
            }
            return response.statusCode() == 200;
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    /**
     * @param size Cloudstack passes this value as units of GB
     */
    @Override
    public void setBucketQuota(String bucketName, long storeId, long size) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        try {
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
                    .append("<Quota>\n")
                    .append("  <StorageQuota>").append(1024 * 1024 * 1024 * size).append("</StorageQuota>\n")
                    .append("</Quota>");
            String body = bodyBuilder.toString();
            byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(UTF_8));
            String base64 = Base64.getEncoder().encodeToString(md5);
            StringBuilder data = new StringBuilder()
                    .append("PUT").append("\n")
                    .append(base64).append("\n")
                    .append("application/xml").append("\n")
                    .append(timestamp).append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("quota");
            URI tmp = new URI(endpoint);
            StringBuilder requestString = new StringBuilder()
                    .append(tmp.getScheme()).append("://").append(bucketName).append(".").append(tmp.getHost())
                    .append('?').append("quota");
            URI quotaUri = new URI(requestString.toString());
            HttpRequest request = authorizationHeaders(quotaUri, timestamp, accountAccessKey, accountSecretKey, data)
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .setHeader(CONTENT_MD5, base64)
                    .setHeader(CONTENT_TYPE, "application/xml")
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println("setBucketQuota === " + response.statusCode());
            if (response.statusCode() != 200) {
                System.err.println(response.body());
                System.err.println("setBucketQuota ===");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | URISyntaxException | IOException | InterruptedException | KeyManagementException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public Map<String, Long> getAllBucketsUsage(long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        Map<String, Long> usage = new HashMap<>();
        List<Bucket> buckets = listBuckets(storeId);
        for (Bucket bucket : buckets) {
            try {
                Long[] storageInfo = getStorageInfo(bucket.getName(), new URI(endpoint), accountAccessKey, accountSecretKey);
                usage.put(bucket.getName(), storageInfo[1]);
            } catch (URISyntaxException | NoSuchAlgorithmException | InvalidKeyException | KeyManagementException | IOException | InterruptedException ex) {
                usage.put(bucket.getName(), -1L);
            }
        }
        return usage;
    }

    private HttpRequest.Builder authorizationHeaders(URI uri, String timestamp, String accountAccessKey, String accountSecretKey, StringBuilder data) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        String SIGNATURE_METHOD = "HmacSHA1";
        Mac mac = Mac.getInstance(SIGNATURE_METHOD);
        mac.init(new SecretKeySpec(accountSecretKey.getBytes(UTF_8), SIGNATURE_METHOD));
        String signature = Base64.getEncoder().encodeToString(mac.doFinal(data.toString().getBytes(UTF_8)));
        return HttpRequest.newBuilder(uri)
                .setHeader("Authorization", "OBS " + accountAccessKey + ":" + signature)
                .setHeader("Date", timestamp)
                .version(HttpClient.Version.HTTP_2)
                .timeout(Duration.ofSeconds(10));
    }

    /**
     * Huawei Object Storage has separate interfaces for manipulating buckets
     * and manipulating accounts and users which is actually a cool feature for
     * security: Our bucket manipulation URL is accessible from the internet
     * whereas our account and user manipulation URL is only accessible from
     * within our private networks where the Cloudstack management server is
     * located.
     *
     * When I tried to put both URLs on the same host and port the object
     * storage interpreted "/poe/rest" as a bucket and not as the account and
     * user administration endpoint. Therefore I had to separate the
     * host-and-port parts of the URLs and hard-code the URL for manipulating
     * accounts and users into the code here. I hope that Cloudstack will at
     * some time in the future offer an optional input field to enter this
     * for-now-hard-coded URL when creating the object storage in the UI so that
     * it no longer needs to be hard-coded.
     *
     * Huawei has a three-tiered approach to user management: The "admin" (root
     * superuser) creates accounts (an organization) which in turn may create
     * users (people within the organization). Accounts can see and manipulate
     * everything belonging to their account whereas users may only see and
     * manipulate those resources of the account which they have been
     * specifically granted permission for. So, for example, an account may list
     * all buckets belonging to its account whereas users in contrast may not
     * list buckets. Users must operate directly on the bucket they have been
     * granted permission for and cannot access anything higher up in the
     * hierarchy (e. g. the parent directory or path of the bucket "../").
     *
     * It seems as though Ceph and Minio only have a two-tiered approach to user
     * management meaning I had to decide whether to create accounts or users. I
     * chose to create accounts instead of users in order to prevent S3 clients
     * from failing because their "listBuckets" calls fail. But only one access
     * key may be specified and when I use the "root admin" key - which can
     * create accounts - then creating the object store fails because no account
     * was specified for which the bucket was to be created. So, I had to revert
     * back to creating users.
     *
     * @return true when the account exists or is created, false otherwise
     */
    @Override
    public boolean createUser(long accountId, long storeId) {
//        return account(accountId, storeId);
        return user(accountId, storeId);
    }

    private boolean user(long accountId, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        Account account = _accountDao.findById(accountId);
        String userId = account.getUuid();
        String userName = account.getAccountName();

        try {
            URI poeEndpointUri = new URI("https://poe-obs.scsynergy.net:9443/poe/rest");
            URI createUserUri = new URI(userRequestString("CreateUser", poeEndpointUri, accountAccessKey, accountSecretKey, userId, userName, null, null));
            HttpRequest request = HttpRequest.newBuilder(createUserUri)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(10))
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                JSONObject createdUser = jsonXml
                        .getJSONObject("CreateUserResponse")
                        .getJSONObject("CreateUserResult")
                        .getJSONObject("User");
                userId = createdUser.getString("UserId");

                String userPermissionPolicyName = "AccessAllPolicy";
                String userPermissionPolicy = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}";
                URI setUserPermissionPolicyUri = new URI(userRequestString("PutUserPolicy", poeEndpointUri, accountAccessKey, accountSecretKey, userId, userName, userPermissionPolicyName, userPermissionPolicy));
                HttpRequest setUserPermissionPolicyRequest = HttpRequest.newBuilder()
                        .uri(setUserPermissionPolicyUri)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = getHttpClient().send(setUserPermissionPolicyRequest, HttpResponse.BodyHandlers.ofString());
                jsonXml = XML.toJSONObject(response.body());
                System.err.println("------------");
                System.err.println(jsonXml.toString(4));
                System.err.println("============");

                URI createAccessKeyUri = new URI(userRequestString("CreateAccessKey", poeEndpointUri, accountAccessKey, accountSecretKey, userId, userName, null, null));
                HttpRequest createAccessKeyRequest = HttpRequest.newBuilder()
                        .uri(createAccessKeyUri)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(10))
                        .build();
                response = getHttpClient().send(createAccessKeyRequest, HttpResponse.BodyHandlers.ofString());
                jsonXml = XML.toJSONObject(response.body());
                JSONObject createdAccessKey = jsonXml
                        .getJSONObject("CreateAccessKeyResponse")
                        .getJSONObject("CreateAccessKeyResult")
                        .getJSONObject("AccessKey");
                String userame = createdAccessKey.getString("UserName");
                if (userName.equals(userame)) {
                    String ak = createdAccessKey.getString("AccessKeyId");
                    String sk = createdAccessKey.getString("SecretAccessKey");
                    // Store user credentials
                    Map<String, String> details = new HashMap<>();
                    details.put(ACCOUNT_ACCESS_KEY, ak);
                    details.put(ACCOUNT_SECRET_KEY, sk);
                    _accountDetailsDao.persist(accountId, details);
                    System.err.println("createUser " + userId + " ::: " + userName + " ===");
                    return true;
                }
            } else if (response.statusCode() == 409) {
                logger.debug("Skipping user creation as the user ID already exists in Huawei OBS store: " + userId);
                return true;
            }
        } catch (NoSuchAlgorithmException | KeyManagementException | InvalidKeyException | URISyntaxException | IOException | InterruptedException ex) {
            throw new CloudRuntimeException(ex);
        }
        return false;
    }

    private String userRequestString(String action, URI poeEndpoint, String poeAccessKeyId, String poeAccessKeySecret, String userId, String userName, String userPermissionPolicyName, String userPermissionPolicy) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, String> signParameters = parameters(action, poeAccessKeyId, null, null, userId, userName, userPermissionPolicyName, userPermissionPolicy);
        StringBuilder requestString = new StringBuilder();
        requestString.append(poeEndpoint.getScheme()).append("://").append(poeEndpoint.getHost()).append(":").append(poeEndpoint.getPort());
        requestString.append(urlEncode(poeEndpoint.getPath(), true));
        requestString.append('?');
        requestString.append("Action=").append(urlEncode(signParameters.get("Action"), false));
        if (userName != null && !userName.isBlank()) {
            requestString.append("&").append("UserName=").append(urlEncode(signParameters.get("UserName"), false));
        }
        if (userPermissionPolicyName != null && !userPermissionPolicyName.isBlank()) {
            requestString.append("&").append("PolicyName=").append(urlEncode(signParameters.get("PolicyName"), false));
        }
        if (userPermissionPolicy != null && !userPermissionPolicy.isBlank()) {
            requestString.append("&").append("PolicyDocument=").append(urlEncode(signParameters.get("PolicyDocument"), false));
        }
        if (userId != null && !userId.isBlank()) {
            requestString.append("&").append("AccessKeyId=").append(urlEncode(signParameters.get("AccessKeyId"), false));
        }
        requestString.append("&").append("POEAccessKeyId=").append(urlEncode(signParameters.get("POEAccessKeyId"), false));
        requestString.append("&").append("SignatureMethod=").append(urlEncode(signParameters.get("SignatureMethod"), false));
        requestString.append("&").append("SignatureVersion=").append(urlEncode(signParameters.get("SignatureVersion"), false));
        requestString.append("&").append("Timestamp=").append(urlEncode(signParameters.get("Timestamp"), false));
        requestString.append("&").append("Signature=");
        String signature = sign("GET", poeEndpoint, signParameters, poeAccessKeySecret);
        signature = urlEncode(signature, false);
        requestString.append(signature);
        return requestString.toString();
    }

    private Map<String, String> parameters(String action, String poeAccessKeyId, String accountId, String accountName, String userId, String userName, String userPermissionPolicyName, String userPermissionPolicy) {
        SortedMap<String, String> parameters = new TreeMap<>();
        parameters.put("Action", action);
        if (accountId != null && !accountId.isBlank()) {
            parameters.put("AccountId", accountId);
        }
        if ("CreateAccount".equals(action) && accountName != null && !accountName.isBlank()) {
            parameters.put("AccountName", accountName);
        }
        if (userId != null && !userId.isBlank()) {
            parameters.put("AccessKeyId", userId);
        }
        if (userName != null && !userName.isBlank()) {
            parameters.put("UserName", userName);
        }
        if (userPermissionPolicyName != null && !userPermissionPolicyName.isBlank()) {
            parameters.put("PolicyName", userPermissionPolicyName);
        }
        if (userPermissionPolicy != null && !userPermissionPolicy.isBlank()) {
            parameters.put("PolicyDocument", userPermissionPolicy);
        }
        parameters.put("POEAccessKeyId", poeAccessKeyId);
        parameters.put("SignatureMethod", POE_SIGNATURE_METHOD);
        parameters.put("SignatureVersion", SIGNATURE_VERSION);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String timestamp = df.format(new Date());
        parameters.put("Timestamp", timestamp);
        return parameters;
    }

    private String urlEncode(String value, boolean path) {
        try {
            String encoded = URLEncoder.encode(value, UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
            if (path) {
                encoded = encoded.replace("%2F", "/");
            }
            return encoded;
        } catch (UnsupportedEncodingException ex) {
            return null;
        }
    }

    private String sign(String httpMethod, URI poeEndpoint, Map<String, String> signParameters, String secretKey) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder data = new StringBuilder();
        data.append(httpMethod).append("\n");
        data.append(poeEndpoint.getHost()).append(":").append(poeEndpoint.getPort()).append("\n");
        data.append(urlEncode(poeEndpoint.getPath(), true)).append("\n");
        data.append(getCanonicalizedQueryString(signParameters));
        String stringToSign = data.toString();
        Mac mac = Mac.getInstance(POE_SIGNATURE_METHOD);
        mac.init(new SecretKeySpec(secretKey.getBytes(Charset.defaultCharset()), POE_SIGNATURE_METHOD));
        return Base64.getEncoder().encodeToString(mac.doFinal(stringToSign.getBytes(UTF_8)));
    }

    private String getCanonicalizedQueryString(Map<String, String> parameters) {
        StringBuilder builder = new StringBuilder();
        Iterator<Map.Entry<String, String>> entries = parameters.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<String, String> entry = entries.next();
            String key = entry.getKey();
            String value = entry.getValue();
            builder.append(urlEncode(key, false));
            builder.append("=");
            builder.append(urlEncode(value, false));
            if (entries.hasNext()) {
                builder.append("&");
            }
        }
        return builder.toString();
    }

    protected String[] getAccessSecretKeysEndpoint(long storeId) {
        ObjectStoreVO store = _storeDao.findById(storeId);
        String endpoint = store.getUrl();
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String clientAccessKey = storeDetails.get(OBJECT_STORE_ACCESS_KEY);
        String clientSecretKey = storeDetails.get(OBJECT_STORE_SECRET_KEY);
        return new String[]{clientAccessKey, clientSecretKey, endpoint};
    }

    protected HttpClient getHttpClient() throws NoSuchAlgorithmException, KeyManagementException {
        if (httpClient == null) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, TRUST_ANY_CERTIFICATES, new SecureRandom());
            httpClient = HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(10))
                    .build();
        }
        return httpClient;
    }

    /**
     * For future use if we want to switch back to creating accounts.
     */
    private boolean account(long accountId, long storeId) {
        String[] accessSecretKeysEndpoint = getAccessSecretKeysEndpoint(storeId);
        String accountAccessKey = accessSecretKeysEndpoint[0];
        String accountSecretKey = accessSecretKeysEndpoint[1];
        String endpoint = accessSecretKeysEndpoint[2]; // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket

        Account account = _accountDao.findById(accountId);
        String accountID = account.getUuid();
        String accountName = account.getAccountName();

        try {
            URI poeEndpointUri = new URI("https://poe-obs.scsynergy.net:9443/poe/rest");
            URI createAccountUri = new URI(accountRequestString("CreateAccount", poeEndpointUri, accountAccessKey, accountSecretKey, accountID, accountName));
            HttpRequest request = HttpRequest.newBuilder(createAccountUri)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(10))
                    .build();
            HttpResponse<String> response = getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                JSONObject createdAccount = jsonXml
                        .getJSONObject("CreateAccountResponse")
                        .getJSONObject("CreateAccountResult")
                        .getJSONObject("Account");
                int accountid = createdAccount.getInt("AccountId");
                if (Integer.parseInt(accountID) == accountid) {
                    URI createAccessKeyUri = new URI(accountRequestString("CreateAccessKey", poeEndpointUri, accountAccessKey, accountSecretKey, accountID, accountName));
                    HttpRequest createAccessKeyRequest = HttpRequest.newBuilder()
                            .uri(createAccessKeyUri)
                            .GET()
                            .version(HttpClient.Version.HTTP_2)
                            .timeout(Duration.ofSeconds(10))
                            .build();
                    response = getHttpClient().send(createAccessKeyRequest, HttpResponse.BodyHandlers.ofString());
                    jsonXml = XML.toJSONObject(response.body());
                    JSONObject createdAccessKey = jsonXml
                            .getJSONObject("CreateAccessKeyResponse")
                            .getJSONObject("CreateAccessKeyResult")
                            .getJSONObject("AccessKey");
                    accountid = createdAccessKey.getInt("AccountId");
                    if (Integer.parseInt(accountID) == accountid) {
                        String ak = createdAccessKey.getString("AccessKeyId");
                        String sk = createdAccessKey.getString("SecretAccessKey");
                        // Store user credentials
                        Map<String, String> details = new HashMap<>();
                        details.put(ACCOUNT_ACCESS_KEY, ak);
                        details.put(ACCOUNT_SECRET_KEY, sk);
                        _accountDetailsDao.persist(accountId, details);
                        return true;
                    }
                }
            } else if (response.statusCode() == 409) {
                logger.debug("Skipping account creation as the account ID already exists in Huawei OBS store: " + accountID);
                return true;
            }
        } catch (NoSuchAlgorithmException | KeyManagementException | InvalidKeyException | URISyntaxException | IOException | InterruptedException ex) {
            throw new CloudRuntimeException(ex);
        }
        return false;
    }

    /**
     * For future use if we want to switch back to creating accounts.
     */
    private String accountRequestString(String action, URI poeEndpoint, String poeAccessKeyId, String poeAccessKeySecret, String accountId, String accountName) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, String> signParameters = parameters(action, poeAccessKeyId, accountId, accountName, null, null, null, null);
        StringBuilder requestString = new StringBuilder();
        requestString.append(poeEndpoint.getScheme()).append("://").append(poeEndpoint.getHost()).append(":").append(poeEndpoint.getPort());
        requestString.append(urlEncode(poeEndpoint.getPath(), true));
        requestString.append('?');
        requestString.append("Action=").append(urlEncode(signParameters.get("Action"), false));
        requestString.append("&").append("AccountId=").append(urlEncode(signParameters.get("AccountId"), false));
        if ("CreateAccount".equals(action)) {
            requestString.append("&").append("AccountName=").append(urlEncode(signParameters.get("AccountName"), false));
        }
        requestString.append("&").append("POEAccessKeyId=").append(urlEncode(signParameters.get("POEAccessKeyId"), false));
        requestString.append("&").append("SignatureMethod=").append(urlEncode(signParameters.get("SignatureMethod"), false));
        requestString.append("&").append("SignatureVersion=").append(urlEncode(signParameters.get("SignatureVersion"), false));
        requestString.append("&").append("Timestamp=").append(urlEncode(signParameters.get("Timestamp"), false));
        requestString.append("&").append("Signature=");
        String signature = sign("GET", poeEndpoint, signParameters, poeAccessKeySecret);
        signature = urlEncode(signature, false);
        requestString.append(signature);
        return requestString.toString();
    }
}
