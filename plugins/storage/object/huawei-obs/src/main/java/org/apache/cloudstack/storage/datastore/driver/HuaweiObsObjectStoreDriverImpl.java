package org.apache.cloudstack.storage.datastore.driver;

import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.BucketPolicy;
import com.amazonaws.services.s3.model.CanonicalGrantee;
import com.amazonaws.services.s3.model.Grant;
import com.amazonaws.services.s3.model.Grantee;
import com.amazonaws.services.s3.model.GroupGrantee;
import com.amazonaws.services.s3.model.Owner;
import com.amazonaws.services.s3.model.Permission;
import com.cloud.agent.api.to.DataStoreTO;
import com.cloud.storage.BucketVO;
import com.cloud.storage.dao.BucketDao;
import com.cloud.user.Account;
import com.cloud.user.AccountDetailsDao;
import com.cloud.user.dao.AccountDao;
import com.cloud.utils.exception.CloudRuntimeException;
import com.obs.services.ObsClient;
import com.obs.services.model.BucketEncryption;
import com.obs.services.model.BucketQuota;
import com.obs.services.model.BucketStorageInfo;
import com.obs.services.model.BucketVersioningConfiguration;
import com.obs.services.model.CreateBucketRequest;
import com.obs.services.model.GrantAndPermission;
import com.obs.services.model.GranteeInterface;
import com.obs.services.model.ListBucketsRequest;
import com.obs.services.model.ObjectListing;
import com.obs.services.model.ObsBucket;
import com.obs.services.model.SSEAlgorithmEnum;
import com.obs.services.model.VersioningStatusEnum;
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.time.Duration;
import org.apache.cloudstack.engine.subsystem.api.storage.DataStore;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreDao;
import org.apache.cloudstack.storage.datastore.db.ObjectStoreDetailsDao;
import org.apache.cloudstack.storage.object.BaseObjectStoreDriverImpl;
import org.apache.cloudstack.storage.object.Bucket;
import org.apache.cloudstack.storage.object.BucketObject;
import org.apache.commons.codec.binary.Base64;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.stream.Stream;
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

    private static final String ACCESS_KEY = "accesskey";
    private static final String SECRET_KEY = "secretkey";
    private static final String OBS_ACCESS_KEY = "huawei-obs-accesskey";
    private static final String OBS_SECRET_KEY = "huawei-obs-secretkey";

    private static final String SIGNATURE_METHOD = "HmacSHA1";
    private static final String SIGNATURE_VERSION = "2";
    private static final String CHARSET_UTF_8 = "UTF-8";
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

        if ((_accountDetailsDao.findDetail(accountId, OBS_ACCESS_KEY) == null) || (_accountDetailsDao.findDetail(accountId, OBS_SECRET_KEY) == null)) {
            throw new CloudRuntimeException("Bucket access credentials unavailable for account: " + account.getAccountName());
        }

        try (ObsClient obsClient = getObsClient(storeId)) {
            String bucketName = bucket.getName();

            if (obsClient.headBucket(bucketName)) {
                throw new CloudRuntimeException("A bucket with the name " + bucketName + " already exists");
            }

            CreateBucketRequest createBucketRequest = new CreateBucketRequest(bucketName);
            createBucketRequest.setAcl(com.obs.services.model.AccessControlList.REST_CANNED_PUBLIC_READ_WRITE);
            obsClient.createBucket(createBucketRequest);

            BucketVO bucketVO = _bucketDao.findById(bucket.getId());
            String accountAccessKey = _accountDetailsDao.findDetail(accountId, OBS_ACCESS_KEY).getValue();
            String accountSecretKey = _accountDetailsDao.findDetail(accountId, OBS_SECRET_KEY).getValue();
            String endpoint = _storeDao.findById(storeId).getUrl();
            String scheme = new URI(endpoint).getScheme() + "://";
            String everythingelse = endpoint.substring(scheme.length());
            bucketVO.setAccessKey(accountAccessKey);
            bucketVO.setSecretKey(accountSecretKey);
            bucketVO.setBucketURL(scheme + bucketName + "." + everythingelse);
            _bucketDao.update(bucket.getId(), bucketVO);
            return bucket;
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public List<Bucket> listBuckets(long storeId) {
        List<Bucket> bucketsList = new ArrayList<>();
        try (ObsClient obsClient = getObsClient(storeId)) {
            ListBucketsRequest request = new ListBucketsRequest();
            for (ObsBucket obsBucket : obsClient.listBuckets(request)) {
                Bucket bucket = new BucketObject();
                bucket.setName(obsBucket.getBucketName());
                bucketsList.add(bucket);
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return bucketsList;
    }

    @Override
    public boolean deleteBucket(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {

            if (!obsClient.headBucket(bucketName)) {
                throw new CloudRuntimeException("Bucket does not exist: " + bucketName);
            }

            ObjectListing objectListing = obsClient.listObjects(bucketName);
            if (objectListing == null || objectListing.getObjects().isEmpty()) {
                obsClient.deleteBucket(bucketName);
            } else {
                throw new CloudRuntimeException("Bucket " + bucketName + " cannot be deleted because it is not empty");
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public AccessControlList getBucketAcl(String bucketName, long storeId) {
        AccessControlList accessControlList = new AccessControlList();
        try (ObsClient obsClient = getObsClient(storeId)) {
            com.obs.services.model.AccessControlList obsAccessControlList = obsClient.getBucketAcl(bucketName);
            com.obs.services.model.Owner obsOwner = obsAccessControlList.getOwner();
            Owner owner = new Owner(obsOwner.getId(), obsOwner.getDisplayName());
            accessControlList.setOwner(owner);
            for (GrantAndPermission grantAndPermission : obsAccessControlList.getGrantAndPermissions()) {
                com.obs.services.model.Permission obsPermission = grantAndPermission.getPermission();
                Permission permission = castPermission(obsPermission);
                GranteeInterface granteeInterface = grantAndPermission.getGrantee();
                if (granteeInterface instanceof com.obs.services.model.CanonicalGrantee) {
                    Grantee grantee = new CanonicalGrantee(granteeInterface.getIdentifier());
                    accessControlList.grantPermission(grantee, permission);
                } else if (granteeInterface instanceof com.obs.services.model.GroupGrantee) {
                    com.obs.services.model.GroupGrantee obsGroupGrantee = (com.obs.services.model.GroupGrantee) granteeInterface;
                    if (obsGroupGrantee.getGroupGranteeType() == com.obs.services.model.GroupGranteeEnum.ALL_USERS) {
                        accessControlList.grantPermission(GroupGrantee.AllUsers, permission);
                    } else if (obsGroupGrantee.getGroupGranteeType() == com.obs.services.model.GroupGranteeEnum.LOG_DELIVERY) {
                        accessControlList.grantPermission(GroupGrantee.LogDelivery, permission);
                    } else if (obsGroupGrantee.getGroupGranteeType() == com.obs.services.model.GroupGranteeEnum.AUTHENTICATED_USERS) {
                        accessControlList.grantPermission(GroupGrantee.AuthenticatedUsers, permission);
                    }
                }
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return accessControlList;
    }

    private Permission castPermission(com.obs.services.model.Permission obsPermission) {
        if (com.obs.services.model.Permission.PERMISSION_FULL_CONTROL == obsPermission) {
            return Permission.FullControl;
        } else if (com.obs.services.model.Permission.PERMISSION_READ == obsPermission) {
            return Permission.Read;
        } else if (com.obs.services.model.Permission.PERMISSION_READ_ACP == obsPermission) {
            return Permission.ReadAcp;
        } else if (com.obs.services.model.Permission.PERMISSION_WRITE == obsPermission) {
            return Permission.Write;
        } else if (com.obs.services.model.Permission.PERMISSION_WRITE_ACP == obsPermission) {
            return Permission.WriteAcp;
        }
        return Permission.FullControl;
    }

    private com.obs.services.model.Permission castPermission(Permission permission) {
        if (Permission.FullControl == permission) {
            return com.obs.services.model.Permission.PERMISSION_FULL_CONTROL;
        } else if (Permission.Read == permission) {
            return com.obs.services.model.Permission.PERMISSION_READ;
        } else if (Permission.ReadAcp == permission) {
            return com.obs.services.model.Permission.PERMISSION_READ_ACP;
        } else if (Permission.Write == permission) {
            return com.obs.services.model.Permission.PERMISSION_WRITE;
        } else if (Permission.WriteAcp == permission) {
            return com.obs.services.model.Permission.PERMISSION_WRITE_ACP;
        }
        return com.obs.services.model.Permission.PERMISSION_FULL_CONTROL;
    }

    @Override
    public void setBucketAcl(String bucketName, AccessControlList accessControlList, long storeId) {
        com.obs.services.model.AccessControlList obsAccessControlList = new com.obs.services.model.AccessControlList();
        Owner owner = accessControlList.getOwner();
        com.obs.services.model.Owner obsOwner = new com.obs.services.model.Owner();
        obsOwner.setId(owner.getId());
        obsOwner.setDisplayName(owner.getDisplayName());
        obsAccessControlList.setOwner(obsOwner);
        for (Grant grant : accessControlList.getGrantsAsList()) {
            if (grant.getGrantee() instanceof CanonicalGrantee) {
                com.obs.services.model.CanonicalGrantee canonicalGrantee = new com.obs.services.model.CanonicalGrantee(grant.getGrantee().getIdentifier());
                obsAccessControlList.grantPermission(canonicalGrantee, castPermission(grant.getPermission()));
            } else if (grant.getGrantee() instanceof GroupGrantee) {
                GroupGrantee groupGrantee = (GroupGrantee) grant.getGrantee();
                if (GroupGrantee.AllUsers == groupGrantee) {
                    obsAccessControlList.grantPermission(com.obs.services.model.GroupGrantee.ALL_USERS, castPermission(grant.getPermission()));
                } else if (GroupGrantee.LogDelivery == groupGrantee) {
                    obsAccessControlList.grantPermission(com.obs.services.model.GroupGrantee.LOG_DELIVERY, castPermission(grant.getPermission()));
                } else if (GroupGrantee.AuthenticatedUsers == groupGrantee) {
                    obsAccessControlList.grantPermission(com.obs.services.model.GroupGrantee.AUTHENTICATED_USERS, castPermission(grant.getPermission()));
                }

            }
        }
        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.setBucketAcl(bucketName, obsAccessControlList);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public void setBucketPolicy(String bucketName, String policy, long storeId) {
        if (policy.equalsIgnoreCase("public") || policy.equalsIgnoreCase("private")) {
            StringBuilder publicPolicyBuilder = new StringBuilder();
            publicPolicyBuilder.append("{\n");
            publicPolicyBuilder.append("    \"Statement\": [\n");
            publicPolicyBuilder.append("        {\n");
            if (policy.equalsIgnoreCase("public")) {
                publicPolicyBuilder.append("            \"Effect\": \"Allow\",\n");
            } else if (policy.equalsIgnoreCase("private")) {
                publicPolicyBuilder.append("            \"Effect\": \"Deny\",\n");
            }
            publicPolicyBuilder.append("            \"Action\": \"*\",\n");
            publicPolicyBuilder.append("            \"Principal\": \"*\",\n");
            publicPolicyBuilder.append("            \"Resource\": [\"arn:aws:s3:::").append(bucketName).append("/*\"]\n");
            publicPolicyBuilder.append("        }\n");
            publicPolicyBuilder.append("    ]\n");
            publicPolicyBuilder.append("}\n");
            policy = publicPolicyBuilder.toString();
        }

        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.setBucketPolicy(bucketName, policy);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public BucketPolicy getBucketPolicy(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            String policy = obsClient.getBucketPolicy(bucketName);
            BucketPolicy bucketPolicy = new BucketPolicy();
            bucketPolicy.setPolicyText(policy);
            return bucketPolicy;
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public void deleteBucketPolicy(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.deleteBucketPolicy(bucketName);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public boolean setBucketEncryption(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            BucketEncryption bucketEncryption = new BucketEncryption(SSEAlgorithmEnum.KMS);
            obsClient.setBucketEncryption(bucketName, bucketEncryption);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public boolean deleteBucketEncryption(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.deleteBucketEncryption(bucketName);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public boolean setBucketVersioning(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            BucketVersioningConfiguration bucketVersioningConfiguration = new BucketVersioningConfiguration(VersioningStatusEnum.ENABLED);
            obsClient.setBucketVersioning(bucketName, bucketVersioningConfiguration);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public boolean deleteBucketVersioning(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            BucketVersioningConfiguration bucketVersioningConfiguration = new BucketVersioningConfiguration(VersioningStatusEnum.SUSPENDED);
            obsClient.setBucketVersioning(bucketName, bucketVersioningConfiguration);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public void setBucketQuota(String bucketName, long storeId, long size) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            BucketQuota quota = new BucketQuota();
            quota.setBucketQuota(size);
            obsClient.setBucketQuota(bucketName, quota);
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    @Override
    public Map<String, Long> getAllBucketsUsage(long storeId) {
        Map<String, Long> allBucketsUsage = new HashMap<>();
        try (ObsClient obsClient = getObsClient(storeId)) {
            for (Bucket bucket : listBuckets(storeId)) {
                String bucketName = bucket.getName();
                BucketStorageInfo storageInfo = obsClient.getBucketStorageInfo(bucketName);
                allBucketsUsage.put(bucketName, storageInfo.getSize());
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return allBucketsUsage;
    }

    protected ObsClient getObsClient(long storeId) {
        ObjectStoreVO store = _storeDao.findById(storeId);
        String endpoint = store.getUrl();
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String clientAccessKey = storeDetails.get(ACCESS_KEY);
        String clientSecretKey = storeDetails.get(SECRET_KEY);
        return new ObsClient(clientAccessKey, clientSecretKey, endpoint);
    }

    @Override
    public boolean createUser(long accountId, long storeId) {
        Account account = _accountDao.findById(accountId);
        String newUser = account.getAccountName();
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String endpointString = _storeDao.findById(storeId).getUrl();
        URI endpointUri = URI.create(endpointString);
        String hostPort = endpointUri.getHost() + ":" + endpointUri.getPort();
        String endpoint = endpointUri.getPath();
        String clientAccessKey = storeDetails.get(ACCESS_KEY);
        String clientSecretKey = storeDetails.get(SECRET_KEY);

        try {
            HttpClient httpClient = getHttpClient();
            URI createUserUri = new URI(getRequestString("CreateUser", null, hostPort, endpoint, clientAccessKey, clientSecretKey, newUser));
            URI createAccessKey = new URI(getRequestString("CreateAccessKey", null, hostPort, endpoint, clientAccessKey, clientSecretKey, newUser));
            URI listAccessKeysUri = new URI(getRequestString("ListAccessKeys", null, hostPort, endpoint, clientAccessKey, clientSecretKey, newUser));
            URI deleteUserUri = new URI(getRequestString("DeleteUser", null, hostPort, endpoint, clientAccessKey, clientSecretKey, newUser));
            HttpRequest request = HttpRequest.newBuilder(createUserUri)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println(response.statusCode());
            System.err.println(response.body());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                System.out.println(jsonXml.toString(4));
                JSONObject createdUser = jsonXml
                        .getJSONObject("CreateUserResponse")
                        .getJSONObject("CreateUserResult")
                        .getJSONObject("User");
                HttpRequest createAccessKeyRequest = HttpRequest.newBuilder()
                        .uri(createAccessKey)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = httpClient.send(createAccessKeyRequest, HttpResponse.BodyHandlers.ofString());
                System.err.println(response.statusCode());
                System.err.println(response.body());
                jsonXml = XML.toJSONObject(response.body());
                System.out.println(jsonXml.toString(4));
                JSONObject createdAccessKey = jsonXml
                        .getJSONObject("CreateAccessKeyResponse")
                        .getJSONObject("CreateAccessKeyResult")
                        .getJSONObject("AccessKey");

                String status = createdAccessKey.getString("");
                String ak = createdAccessKey.getString("");
                String sk = createdAccessKey.getString("");
                // Store user credentials
                Map<String, String> details = new HashMap<>();
                details.put(OBS_ACCESS_KEY, ak);
                details.put(OBS_SECRET_KEY, sk);
                _accountDetailsDao.persist(accountId, details);
            } else if (response.statusCode() == 409) {
                request = HttpRequest.newBuilder(listAccessKeysUri)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                System.err.println(response.statusCode());
                System.err.println(response.body());
                JSONObject jsonXml = XML.toJSONObject(response.body());
                System.out.println(jsonXml.toString(4));
                JSONObject accessKeyMetadata = jsonXml
                        .getJSONObject("ListAccessKeysResponse")
                        .getJSONObject("ListAccessKeysResult")
                        .getJSONObject("AccessKeyMetadata");

                Stream<String> accessKeyIds = Stream.empty();
                JSONObject member = accessKeyMetadata.optJSONObject("member");
                JSONArray members = accessKeyMetadata.optJSONArray("member");
                if (member != null) {
                    accessKeyIds = Stream.of(member.getString("AccessKeyId"));
                } else if (members != null) {
                    Iterator<Object> iter = members.iterator();
                    accessKeyIds = Stream.generate(() -> null)
                            .takeWhile(i -> iter.hasNext())
                            .map(j -> (JSONObject) iter.next())
                            .map(k -> k.getString("AccessKeyId"));
                }
                for (String tmp : accessKeyIds.toList()) {
                    URI deleteAccessKeyUri = new URI(getRequestString("DeleteAccessKey", tmp, hostPort, endpoint, clientAccessKey, clientSecretKey, newUser));
                    request = HttpRequest.newBuilder(deleteAccessKeyUri)
                            .GET()
                            .version(HttpClient.Version.HTTP_2)
                            .timeout(Duration.ofSeconds(30))
                            .build();
                    response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    System.err.println(response.statusCode());
                    System.err.println(response.body());
                }
                request = HttpRequest.newBuilder(deleteUserUri)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                System.err.println(response.body());
            }
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException | InvalidKeyException | URISyntaxException | InterruptedException ex) {
            logger.debug("Failed to create Huawei OBS user " + newUser, ex);
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    private static Map<String, String> getParameters(String action, String accessKeyId, String accessKey, String username) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("Action", action);
        if (accessKeyId != null && !accessKeyId.isBlank()) {
            parameters.put("AccessKeyId", accessKeyId);
        }
        parameters.put("POEAccessKeyId", accessKey);
        parameters.put("SignatureMethod", SIGNATURE_METHOD);
        parameters.put("SignatureVersion", SIGNATURE_VERSION);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String timestamp = df.format(new Date());
        parameters.put("Timestamp", timestamp);
        if (username != null && !username.isBlank()) {
            parameters.put("UserName", username);
        }
        return parameters;
    }

    private static String getRequestString(String action, String accessKeyId, String hostPort, String endpoint, String accessKey, String secretKey, String username) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, String> signParameters = getParameters(action, accessKeyId, accessKey, username);
        StringBuilder requestString = new StringBuilder();
        requestString.append("https://").append(hostPort);
        requestString.append(urlEncode(endpoint, true));
        requestString.append('?');
        requestString.append("Action=").append(urlEncode(signParameters.get("Action"), false));
        if (accessKeyId != null && !accessKeyId.isBlank()) {
            requestString.append("&").append("AccessKeyId=").append(urlEncode(signParameters.get("AccessKeyId"), false));
        }
        requestString.append("&").append("POEAccessKeyId=").append(urlEncode(signParameters.get("POEAccessKeyId"), false));
        requestString.append("&").append("SignatureMethod=").append(urlEncode(signParameters.get("SignatureMethod"), false));
        requestString.append("&").append("SignatureVersion=").append(urlEncode(signParameters.get("SignatureVersion"), false));
        requestString.append("&").append("Timestamp=").append(urlEncode(signParameters.get("Timestamp"), false));
        if (signParameters.get("UserName") != null) {
            requestString.append("&").append("UserName=").append(urlEncode(signParameters.get("UserName"), false));
        }
        requestString.append("&").append("Signature=");
        String signature = sign("GET", hostPort, endpoint, signParameters, secretKey);
        signature = urlEncode(signature, false);
        requestString.append(signature);
        return requestString.toString();
    }

    public static String urlEncode(String value, boolean path) {
        try {
            String encoded = URLEncoder.encode(value, CHARSET_UTF_8).replace("+", "%20").replace("*", "%2A").replace("%7E", "~");
            if (path) {
                encoded = encoded.replace("%2F", "/");
            }
            return encoded;
        } catch (UnsupportedEncodingException ex) {
            return null;
        }
    }

    private static String sign(String httpMethod, String host, String uri, Map<String, String> signParameters, String secretKey) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder data = new StringBuilder();
        data.append(httpMethod).append("\n");
        data.append(host).append("\n");
        data.append(urlEncode(uri, true)).append("\n");
        data.append(getCanonicalizedQueryString(signParameters));
        String stringToSign = data.toString();
//        System.err.println("---------------");
//        System.err.println(stringToSign);
//        System.err.println("===============");
        return sign(stringToSign.getBytes(CHARSET_UTF_8), secretKey, SIGNATURE_METHOD);
    }

    private static String getCanonicalizedQueryString(Map<String, String> parameters) {
        SortedMap<String, String> sorted = new TreeMap<>();
        sorted.putAll(parameters);
        StringBuilder builder = new StringBuilder();
        Iterator<Map.Entry<String, String>> pairs = sorted.entrySet().iterator();
        while (pairs.hasNext()) {
            Map.Entry<String, String> pair = pairs.next();
            String key = pair.getKey();
            String value = pair.getValue();
            builder.append(urlEncode(key, false));
            builder.append("=");
            builder.append(urlEncode(value, false));
            if (pairs.hasNext()) {
                builder.append("&");
            }
        }
        return builder.toString();
    }

    private static String sign(byte[] data, String key, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key.getBytes(Charset.defaultCharset()), algorithm));
        byte[] signature = Base64.encodeBase64(mac.doFinal(data));
        return new String(signature, Charset.defaultCharset());
    }

    private HttpClient getHttpClient() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TRUST_ANY_CERTIFICATES, new SecureRandom());
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        return httpClient;
    }

    public static final TrustManager TRUST_ANY_CERTIFICATE = new X509ExtendedTrustManager() {
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
    public static final TrustManager[] TRUST_ANY_CERTIFICATES = new TrustManager[]{TRUST_ANY_CERTIFICATE};
}
