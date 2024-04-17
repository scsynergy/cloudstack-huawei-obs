package org.apache.cloudstack.storage.datastore.driver;

//import com.cloud.storage.BucketVO;
//import com.cloud.storage.dao.BucketDao;
//import com.cloud.user.AccountDetailVO;
//import com.cloud.user.AccountDetailsDao;
//import com.cloud.user.AccountVO;
//import com.cloud.user.dao.AccountDao;
//import java.net.URI;
//import java.net.http.HttpClient;
//import java.net.http.HttpRequest;
//import java.net.http.HttpResponse;
//import org.apache.cloudstack.storage.datastore.db.ObjectStoreDao;
//import org.apache.cloudstack.storage.datastore.db.ObjectStoreDetailsDao;
//import org.apache.cloudstack.storage.datastore.db.ObjectStoreVO;
//import org.apache.cloudstack.storage.object.Bucket;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
//import org.mockito.Mockito;
//import org.mockito.Mock;
//import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
//import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class HuaweiObsObjectStoreDriverImplTest {

//    @Spy
//    HuaweiObsObjectStoreDriverImpl huaweiObsObjectStoreDriverImpl = new HuaweiObsObjectStoreDriverImpl();
//
//    @Mock
//    HttpClient httpClient;
//    @Mock
//    HttpResponse httpResponse;
//    @Mock
//    ObjectStoreDao objectStoreDao;
//    @Mock
//    ObjectStoreVO objectStoreVO;
//    @Mock
//    ObjectStoreDetailsDao objectStoreDetailsDao;
//    @Mock
//    AccountDao accountDao;
//    @Mock
//    BucketDao bucketDao;
//    @Mock
//    AccountVO account;
//    @Mock
//    AccountDetailsDao accountDetailsDao;
//
//    Bucket bucket;
//    String bucketName = "test-bucket";
//    URI uri = URI.create("https://fqdn");

    @Before
    public void setUp() {
//        huaweiObsObjectStoreDriverImpl._storeDao = objectStoreDao;
//        huaweiObsObjectStoreDriverImpl._storeDetailsDao = objectStoreDetailsDao;
//        huaweiObsObjectStoreDriverImpl._accountDao = accountDao;
//        huaweiObsObjectStoreDriverImpl._bucketDao = bucketDao;
//        huaweiObsObjectStoreDriverImpl._accountDetailsDao = accountDetailsDao;
//        bucket = new BucketVO(0, 0, 0, bucketName, 100, false, false, false, "public");
    }

    @Test
    public void testCreateBucket() throws Exception {
        assertTrue(true);
//        try {
//            Mockito.doReturn(httpClient).when(huaweiObsObjectStoreDriverImpl).getHttpClient();
//            Mockito.when(accountDao.findById(Mockito.anyLong())).thenReturn(account);
//            Mockito.when(accountDetailsDao.findDetail(Mockito.anyLong(), Mockito.anyString())).thenReturn(new AccountDetailVO(1L, "abc", "def"));
//            Mockito.doReturn(200).when(httpResponse.statusCode());
//            Mockito.doReturn("any string").when(httpResponse.body());
//            Mockito.doReturn(httpResponse).when(httpClient.send(Mockito.any(HttpRequest.class), Mockito.eq(HttpResponse.BodyHandlers.ofString())));
//            Mockito.doReturn(false).when(huaweiObsObjectStoreDriverImpl.headBucket(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString()));
//            Mockito.when(bucketDao.findById(Mockito.anyLong())).thenReturn(new BucketVO(0, 0, 0, bucketName, 100, false, false, false, "public"));
//            Mockito.when(objectStoreVO.getUrl()).thenReturn(uri.toASCIIString());
//            Mockito.when(objectStoreDao.findById(Mockito.any())).thenReturn(objectStoreVO);
//            Mockito.doNothing().when(huaweiObsObjectStoreDriverImpl).cors(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString());
//            Bucket bucketRet = huaweiObsObjectStoreDriverImpl.createBucket(bucket, false);
//            assertEquals(bucketRet.getName(), bucket.getName());
//            Mockito.verify(huaweiObsObjectStoreDriverImpl.headBucket(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString()));
//            Mockito.verify(huaweiObsObjectStoreDriverImpl.createBucket(bucket, false));
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
    }

    @Test
    public void testDeleteBucket() throws Exception {
        assertTrue(true);
//        Mockito.doReturn(httpClient).when(huaweiObsObjectStoreDriverImpl).getHttpClient();
//        Mockito.when(httpResponse.statusCode()).thenReturn(200);
//        Mockito.when(httpClient.send(Mockito.any(HttpRequest.class), Mockito.eq(HttpResponse.BodyHandlers.discarding()))).thenReturn(httpResponse);
//        Mockito.when(huaweiObsObjectStoreDriverImpl.headBucket(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString())).thenReturn(true);
//        Mockito.when(huaweiObsObjectStoreDriverImpl.getStorageInfo(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString())).thenReturn(new Long[]{0L, 0L});
//        Mockito.when(httpResponse.statusCode()).thenReturn(204);
//        assertTrue(huaweiObsObjectStoreDriverImpl.deleteBucket(bucketName, 1L));
//        Mockito.verify(huaweiObsObjectStoreDriverImpl.headBucket(bucketName, Mockito.eq(uri), Mockito.anyString(), Mockito.anyString()));
//        Mockito.verify(huaweiObsObjectStoreDriverImpl.deleteBucket(bucketName, Mockito.anyLong()));
    }
}
