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
import com.obs.services.exception.ObsException;
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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
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
import org.apache.commons.codec.binary.Base64;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
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
    private static final String SIGNATURE_METHOD = "HmacSHA1";
    private static final String SIGNATURE_VERSION = "2";
    private static final String CHARSET_UTF_8 = "UTF-8";
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

        if ((_accountDetailsDao.findDetail(accountId, ACCOUNT_ACCESS_KEY) == null) || (_accountDetailsDao.findDetail(accountId, ACCOUNT_SECRET_KEY) == null)) {
            throw new CloudRuntimeException("Bucket access credentials unavailable for account: " + account.getAccountName());
        }

        String bucketName = bucket.getName();
        try (ObsClient obsClient = getObsClient(storeId)) {

            if (obsClient.headBucket(bucketName)) {
                throw new CloudRuntimeException("A bucket with the name " + bucketName + " already exists");
            }

            CreateBucketRequest createBucketRequest = new CreateBucketRequest(bucketName);
            obsClient.createBucket(createBucketRequest);

            BucketVO bucketVO = _bucketDao.findById(bucket.getId());
            String userAccessKey = _accountDetailsDao.findDetail(accountId, ACCOUNT_ACCESS_KEY).getValue();
            String userSecretKey = _accountDetailsDao.findDetail(accountId, ACCOUNT_SECRET_KEY).getValue();
            String endpoint = _storeDao.findById(storeId).getUrl();
            // Cloudstack can only handle path mode (https://fqdn:port/bucketname) but neither domain mode (https://bucketname.fqdn:port) nor mixed mode (https://bucketname.fqdn:port/bucketname)
            bucketVO.setBucketURL(endpoint + "/" + bucketName);
            bucketVO.setAccessKey(userAccessKey);
            bucketVO.setSecretKey(userSecretKey);
            _bucketDao.update(bucket.getId(), bucketVO);
            cors(bucketName, storeId, endpoint);
            return bucket;
        } catch (Exception ex) {
            ex.printStackTrace();
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

    /**
     * When a bucket is created as "private" via the Huawei UI it simply does
     * not have a policy. Trying to read or delete the bucket policy of a
     * "private" bucket results in "404 - The bucket policy does not exist".
     * Huawei's UI has three default policies to choose from: "private", "public
     * read-only" and "public read-write". Since the Cloudstack UI only offers
     * "private" and "public" in the dropdown I chose to map "public" to
     * "public-read-write" and "private" to "public read-only" and mapping the
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
        if (policy == null) {
            return; // nothing needs to be done as this is the default for Huawei Object Storage
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
            publicRead.append("            \"AWS\": [\n");
            publicRead.append("               \"*\"\n");
            publicRead.append("            ]\n");
            publicRead.append("         },\n");
            publicRead.append("         \"Action\": [\n");
            publicRead.append("            \"s3:GetObject\",\n");
            publicRead.append("            \"s3:GetObjectVersion\",\n");
            publicRead.append("            \"s3:ListMultipartUploadParts\",\n");
            publicRead.append("            \"s3:GetObjectAcl\",\n");
            publicRead.append("            \"s3:GetObjectVersionAcl\"\n");
            publicRead.append("         ],\n");
            publicRead.append("         \"Resource\": [\n");
            publicRead.append("            \"arn:aws:s3:::").append(bucketName).append("/*\"\n");
            publicRead.append("         ]\n");
            publicRead.append("      },\n");
            publicRead.append("      {\n");
            publicRead.append("         \"Sid\": \"publicHeadBucketPolicyStatementId\",\n");
            publicRead.append("         \"Effect\": \"Allow\",\n");
            publicRead.append("         \"Principal\": {\n");
            publicRead.append("            \"AWS\": [\n");
            publicRead.append("               \"*\"\n");
            publicRead.append("            ]\n");
            publicRead.append("         },\n");
            publicRead.append("         \"Action\": [\n");
            publicRead.append("            \"s3:HeadBucket\",\n");
            publicRead.append("            \"s3:ListBucket\"\n");
            publicRead.append("         ],\n");
            publicRead.append("         \"Resource\": [\n");
            publicRead.append("            \"arn:aws:s3:::").append(bucketName).append("\"\n");
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
            publicWrite.append("            \"AWS\": [\n");
            publicWrite.append("               \"*\"\n");
            publicWrite.append("            ]\n");
            publicWrite.append("         },\n");
            publicWrite.append("         \"Action\": [\n");
            publicWrite.append("            \"s3:GetObject\",\n");
            publicWrite.append("            \"s3:PutObject\",\n");
            publicWrite.append("            \"s3:GetObjectVersion\",\n");
            publicWrite.append("            \"s3:DeleteObjectVersion\",\n");
            publicWrite.append("            \"s3:DeleteObject\",\n");
            publicWrite.append("            \"s3:ListMultipartUploadParts\",\n");
            publicWrite.append("            \"s3:GetObjectAcl\",\n");
            publicWrite.append("            \"s3:GetObjectVersionAcl\",\n");
            publicWrite.append("            \"s3:PutObjectAcl\",\n");
            publicWrite.append("            \"s3:PutObjectVersionAcl\",\n");
            publicWrite.append("            \"s3:AbortMultipartUpload\"\n");
            publicWrite.append("         ],\n");
            publicWrite.append("         \"Resource\": [\n");
            publicWrite.append("            \"arn:aws:s3:::").append(bucketName).append("/*\"\n");
            publicWrite.append("         ]\n");
            publicWrite.append("      },\n");
            publicWrite.append("      {\n");
            publicWrite.append("         \"Sid\": \"publicHeadBucketPolicyStatementId\",\n");
            publicWrite.append("         \"Effect\": \"Allow\",\n");
            publicWrite.append("         \"Principal\": {\n");
            publicWrite.append("            \"AWS\": [\n");
            publicWrite.append("               \"*\"\n");
            publicWrite.append("            ]\n");
            publicWrite.append("         },\n");
            publicWrite.append("         \"Action\": [\n");
            publicWrite.append("            \"s3:HeadBucket\",\n");
            publicWrite.append("            \"s3:ListBucket\"\n");
            publicWrite.append("         ],\n");
            publicWrite.append("         \"Resource\": [\n");
            publicWrite.append("            \"arn:aws:s3:::").append(bucketName).append("\"\n");
            publicWrite.append("         ]\n");
            publicWrite.append("      }\n");
            publicWrite.append("   ]\n");
            publicWrite.append("}");
            policy = publicWrite.toString();
        }

        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.setBucketPolicy(bucketName, policy);
        } catch (Exception ex) {
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
        try (ObsClient obsClient = getObsClient(storeId)) {
            String policy = obsClient.getBucketPolicy(bucketName);
            BucketPolicy bucketPolicy = new BucketPolicy();
            bucketPolicy.setPolicyText(policy);
            return bucketPolicy;
        } catch (Exception ex) {
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
        } catch (ObsException ex) {
            if (ex.getResponseCode() == 405) {
                logger.debug("No license for bucket level encryption");
                return false;
            } else {
                throw new CloudRuntimeException(ex);
            }
        } catch (Exception ex) {
            throw new CloudRuntimeException(ex);
        }
        return true;
    }

    @Override
    public boolean deleteBucketEncryption(String bucketName, long storeId) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            obsClient.deleteBucketEncryption(bucketName);
        } catch (ObsException ex) {
            if (ex.getResponseCode() == 405) {
                logger.debug("No license for bucket level encryption");
                return false;
            } else {
                throw new CloudRuntimeException(ex);
            }
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

    /**
     * @param size Cloudstack passes this value as units of GB
     */
    @Override
    public void setBucketQuota(String bucketName, long storeId, long size) {
        try (ObsClient obsClient = getObsClient(storeId)) {
            BucketQuota quota = new BucketQuota(1024 * 1024 * 1024 * size);
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
        String clientAccessKey = storeDetails.get(OBJECT_STORE_ACCESS_KEY);
        String clientSecretKey = storeDetails.get(OBJECT_STORE_SECRET_KEY);
        return new ObsClient(clientAccessKey, clientSecretKey, endpoint);
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
     * all buckets belonging to his account whereas users in contrast may not
     * list buckets. Users must operate directly on the bucket they have been
     * granted permission for and cannot access anything higher up in the
     * hierarchy (e. g. the parent directory or path of the bucket "../").
     *
     * It seems as though Ceph and Minio only have a two-tiered approach to user
     * management meaning I had to decide whether to create accounts or users. I
     * chose to create accounts instead of users in order to prevent S3 clients
     * from failing because their "listBuckets" calls fail.
     *
     * @return true when the account exists or is created, false otherwise
     */
    @Override
    public boolean createUser(long accountId, long storeId) {
//        return account(accountId, storeId);
        return user(accountId, storeId);
    }

    private boolean user(long accountId, long storeId) {
        Account account = _accountDao.findById(accountId);
        String userId = account.getUuid();
        String userName = account.getAccountName();
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String endpointString = _storeDao.findById(storeId).getUrl(); // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket
        URI endpointUri = URI.create(endpointString);
        String hostPort = endpointUri.getHost() + ":" + endpointUri.getPort();
        String endpoint = endpointUri.getPath();
        hostPort = "poe-obs.scsynergy.net:9443";
        endpoint = "/poe/rest";
        String clientAccessKey = storeDetails.get(OBJECT_STORE_ACCESS_KEY);
        String clientSecretKey = storeDetails.get(OBJECT_STORE_SECRET_KEY);
        try {
            HttpClient httpClient = getHttpClient();
            URI createUserUri = new URI(userRequestString("CreateUser", hostPort, endpoint, clientAccessKey, clientSecretKey, userId, userName));
            HttpRequest request = HttpRequest.newBuilder(createUserUri)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                JSONObject createdUser = jsonXml
                        .getJSONObject("CreateUserResponse")
                        .getJSONObject("CreateUserResult")
                        .getJSONObject("User");
                userId = createdUser.getString("UserId");
                URI createAccessKeyUri = new URI(userRequestString("CreateAccessKey", hostPort, endpoint, clientAccessKey, clientSecretKey, userId, userName));
                HttpRequest createAccessKeyRequest = HttpRequest.newBuilder()
                        .uri(createAccessKeyUri)
                        .GET()
                        .version(HttpClient.Version.HTTP_2)
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = httpClient.send(createAccessKeyRequest, HttpResponse.BodyHandlers.ofString());
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

    private String userRequestString(String action, String hostPort, String endpoint, String poeAccessKeyId, String poeAccessKeySecret, String userId, String userName) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, String> signParameters = parameters(action, poeAccessKeyId, null, null, userId, userName);
        StringBuilder requestString = new StringBuilder();
        requestString.append("https://").append(hostPort);
        requestString.append(urlEncode(endpoint, true));
        requestString.append('?');
        requestString.append("Action=").append(urlEncode(signParameters.get("Action"), false));
        if (userId != null && !userId.isBlank()) {
            requestString.append("&").append("AccessKeyId=").append(urlEncode(signParameters.get("AccessKeyId"), false));
        }
        requestString.append("&").append("POEAccessKeyId=").append(urlEncode(signParameters.get("POEAccessKeyId"), false));
        requestString.append("&").append("SignatureMethod=").append(urlEncode(signParameters.get("SignatureMethod"), false));
        requestString.append("&").append("SignatureVersion=").append(urlEncode(signParameters.get("SignatureVersion"), false));
        requestString.append("&").append("Timestamp=").append(urlEncode(signParameters.get("Timestamp"), false));
        if (userName != null && !userName.isBlank()) {
            requestString.append("&").append("UserName=").append(urlEncode(signParameters.get("UserName"), false));
        }
        requestString.append("&").append("Signature=");
        String signature = sign("GET", hostPort, endpoint, signParameters, poeAccessKeySecret);
        signature = urlEncode(signature, false);
        requestString.append(signature);
        return requestString.toString();
    }

    private Map<String, String> parameters(String action, String poeAccessKeyId, String accountId, String accountName, String userId, String userName) {
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
        parameters.put("POEAccessKeyId", poeAccessKeyId);
        parameters.put("SignatureMethod", SIGNATURE_METHOD);
        parameters.put("SignatureVersion", SIGNATURE_VERSION);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String timestamp = df.format(new Date());
        parameters.put("Timestamp", timestamp);
        return parameters;
    }

    public String urlEncode(String value, boolean path) {
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

    private String sign(String httpMethod, String host, String uri, Map<String, String> signParameters, String secretKey) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        StringBuilder data = new StringBuilder();
        data.append(httpMethod).append("\n");
        data.append(host).append("\n");
        data.append(urlEncode(uri, true)).append("\n");
        data.append(getCanonicalizedQueryString(signParameters));
        String stringToSign = data.toString();
        Mac mac = Mac.getInstance(SIGNATURE_METHOD);
        mac.init(new SecretKeySpec(secretKey.getBytes(Charset.defaultCharset()), SIGNATURE_METHOD));
        byte[] signature = Base64.encodeBase64(mac.doFinal(stringToSign.getBytes(CHARSET_UTF_8)));
        return new String(signature, Charset.defaultCharset());
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

    protected HttpClient getHttpClient() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, TRUST_ANY_CERTIFICATES, new SecureRandom());
        HttpClient httpClient = HttpClient.newBuilder()
                .sslContext(sslContext)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        return httpClient;
    }

    private static boolean isReachable(NetworkInterface networkInterface, InetAddress localInetAddress, URI endpoint, int timeout) throws IOException {
        if (localInetAddress.isLoopbackAddress() || localInetAddress.isAnyLocalAddress()) {
            return false;
        }
        if (InetAddress.getByName(endpoint.getHost()).isReachable(networkInterface, 50, timeout)) {
            return true;
        }
        int port = endpoint.getPort();
        if (port == -1 && "HTTP".equalsIgnoreCase(endpoint.getScheme())) {
            port = 80;
        } else if (port == -1 && "HTTPS".equalsIgnoreCase(endpoint.getScheme())) {
            port = 443;
        } else if (port < 0) {
            return false;
        }
        try (Socket clientSocket = new Socket()) {
            clientSocket.setSoTimeout(timeout);
            clientSocket.bind(new InetSocketAddress(localInetAddress, 0));
            clientSocket.connect(new InetSocketAddress(endpoint.getHost(), port), timeout);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    protected void cors(String bucketName, long storeId, String endpoint) {
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String accountAccessKey = storeDetails.get(OBJECT_STORE_ACCESS_KEY);
        String accountSecretKey = storeDetails.get(OBJECT_STORE_SECRET_KEY);
        System.err.println(accountAccessKey + " --------------------------------------");
        try {
            URI uri = new URI(endpoint);
            StringBuilder bodyBuilder = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
                    .append("<CORSConfiguration>\n")
                    .append("  <CORSRule>\n")
                    .append("    <AllowedMethod>POST</AllowedMethod>\n")
                    .append("    <AllowedMethod>GET</AllowedMethod>\n")
                    .append("    <AllowedMethod>HEAD</AllowedMethod>\n")
                    .append("    <AllowedMethod>PUT</AllowedMethod>\n")
                    .append("    <AllowedMethod>DELETE</AllowedMethod>\n");
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                if (networkInterface != null && networkInterface.isUp()) {
                    Enumeration<InetAddress> iter = networkInterface.getInetAddresses();
                    while (iter.hasMoreElements()) {
                        InetAddress inetAddress = iter.nextElement();
                        if (isReachable(networkInterface, inetAddress, uri, 5000)) {
                            String connectionsuccessful = inetAddress.getCanonicalHostName().replaceAll("%.+$", "");
                            bodyBuilder.append("    <AllowedOrigin>").append(connectionsuccessful).append("</AllowedOrigin>\n");
                        }
                    }
                }
            }
            bodyBuilder
                    .append("    <MaxAgeSeconds>86400</MaxAgeSeconds>\n")
                    .append("    <AllowedHeader>*</AllowedHeader>\n")
                    .append("  </CORSRule>\n")
                    .append("</CORSConfiguration>");
            String body = bodyBuilder.toString();
            System.err.println(body);
            byte[] md5 = MessageDigest.getInstance("MD5").digest(body.getBytes(CHARSET_UTF_8));
            String base64MD5 = java.util.Base64.getEncoder().encodeToString(md5);
            String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss zzz"));
            StringBuilder data = new StringBuilder()
                    .append("PUT")
                    .append("\n")
                    .append(base64MD5)
                    .append("\n")
                    .append("application/xml")
                    .append("\n")
                    .append(timestamp)
                    .append("\n")
                    .append("/").append(bucketName).append("/")
                    .append('?').append("cors");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(accountSecretKey.getBytes(CHARSET_UTF_8), "HmacSHA1"));
            String signature = java.util.Base64.getEncoder().encodeToString(mac.doFinal(data.toString().getBytes(CHARSET_UTF_8)));
            StringBuilder requestStringBuilder = new StringBuilder()
                    .append("https://").append(bucketName).append(".").append(uri.getHost())
                    .append('?').append("cors");
            URI corsUri = new URI(requestStringBuilder.toString());
            System.err.println("--> " + corsUri.toASCIIString());
            HttpRequest request = HttpRequest.newBuilder(corsUri)
                    .PUT(HttpRequest.BodyPublishers.ofString(body))
                    .setHeader("Authorization", "OBS " + accountAccessKey + ":" + signature)
                    .setHeader("Content-MD5", base64MD5)
                    .setHeader("Content-Type", "application/xml")
                    .setHeader("Date", timestamp)
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpClient httpClient = getHttpClient();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            System.err.println(response.statusCode());
            System.err.println(response.body());
        } catch (InvalidKeyException | NoSuchAlgorithmException | KeyManagementException | URISyntaxException | IOException | InterruptedException ex) {
            throw new CloudRuntimeException(ex);
        }
    }

    /**
     * For future use if we want to switch back to creating accounts.
     */
    private boolean account(long accountId, long storeId) {
        Account account = _accountDao.findById(accountId);
        String accountID = account.getUuid();
        String accountName = account.getAccountName();
        Map<String, String> storeDetails = _storeDetailsDao.getDetails(storeId);
        String endpointString = _storeDao.findById(storeId).getUrl(); // this URL cannot be used for "/poe/rest" because Huawei REST API interprets "/poe" as a bucket
        URI endpointUri = URI.create(endpointString);
        String hostPort = endpointUri.getHost() + ":" + endpointUri.getPort();
        String endpoint = endpointUri.getPath();
        hostPort = "poe-obs.scsynergy.net:9443";
        endpoint = "/poe/rest";
        String clientAccessKey = storeDetails.get(OBJECT_STORE_ACCESS_KEY);
        String clientSecretKey = storeDetails.get(OBJECT_STORE_SECRET_KEY);
        try {
            HttpClient httpClient = getHttpClient();
            URI createAccountUri = new URI(accountRequestString("CreateAccount", hostPort, endpoint, clientAccessKey, clientSecretKey, accountID, accountName));
            HttpRequest request = HttpRequest.newBuilder(createAccountUri)
                    .GET()
                    .version(HttpClient.Version.HTTP_2)
                    .timeout(Duration.ofSeconds(30))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JSONObject jsonXml = XML.toJSONObject(response.body());
                JSONObject createdAccount = jsonXml
                        .getJSONObject("CreateAccountResponse")
                        .getJSONObject("CreateAccountResult")
                        .getJSONObject("Account");
                int accountid = createdAccount.getInt("AccountId");
                if (Integer.parseInt(accountID) == accountid) {
                    URI createAccessKeyUri = new URI(accountRequestString("CreateAccessKey", hostPort, endpoint, clientAccessKey, clientSecretKey, accountID, accountName));
                    HttpRequest createAccessKeyRequest = HttpRequest.newBuilder()
                            .uri(createAccessKeyUri)
                            .GET()
                            .version(HttpClient.Version.HTTP_2)
                            .timeout(Duration.ofSeconds(30))
                            .build();
                    response = httpClient.send(createAccessKeyRequest, HttpResponse.BodyHandlers.ofString());
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
                logger.debug("Skipping user creation as the user ID already exists in Huawei OBS store: " + accountID);
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
    private String accountRequestString(String action, String hostPort, String endpoint, String poeAccessKeyId, String poeAccessKeySecret, String accountId, String accountName) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, String> signParameters = parameters(action, poeAccessKeyId, accountId, accountName, null, null);
        StringBuilder requestString = new StringBuilder();
        requestString.append("https://").append(hostPort);
        requestString.append(urlEncode(endpoint, true));
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
        String signature = sign("GET", hostPort, endpoint, signParameters, poeAccessKeySecret);
        signature = urlEncode(signature, false);
        requestString.append(signature);
        return requestString.toString();
    }
}
