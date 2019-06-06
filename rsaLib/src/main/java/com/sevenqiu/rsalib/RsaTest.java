package com.sevenqiu.rsalib;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;


public class RsaTest {
    public static final String KEY_ALGORITHM = "RSA";
    /**
     * 获取私钥的KEY
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;
    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    private static final String TEST_DATA = "happy everyday";

    /**
     * 生成密钥对(公钥和私钥)
     * *@return
     */

    public static List<KeyPair> genKeyPair() throws Exception {
        List<KeyPair> keyPairList = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            keyPairGen.initialize(1024);
            keyPairList.add(keyPairGen.generateKeyPair());
        }
        return keyPairList;
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥 (BASE64编码)
     * @return
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws
            Exception {
        byte[] keyBytes = Base64Util.decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes != null ? keyBytes : new byte[0]);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 对数据加密
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        // 对数据分段加密
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @return
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64Util.decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes != null ? keyBytes : new byte[0]);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        // 对数据分段解密
        int i = 0;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }


    public static void main(String[] arg) {
        try {
            List<KeyPair> keyPairList = genKeyPair();

            KeyPair keyPairA = keyPairList.get(0);
            RSAPublicKey publicKeyA = (RSAPublicKey) keyPairA.getPublic();
            RSAPrivateKey privateKeyA = (RSAPrivateKey) keyPairA.getPrivate();

            KeyPair keyPairB = keyPairList.get(1);
            RSAPublicKey publicKeyB = (RSAPublicKey) keyPairB.getPublic();
            RSAPrivateKey privateKeyB = (RSAPrivateKey) keyPairB.getPrivate();

            byte[] encryptString = RsaTest.encryptByPublicKey(TEST_DATA.getBytes(), Base64Util.encode(publicKeyA.getEncoded()));
            byte[] decryptString = RsaTest.decryptByPrivateKey(encryptString, Base64Util.encode(privateKeyA.getEncoded()));

            System.out.println("encryptString:" + Base64Util.encode(encryptString));
            System.out.println("decryptString:" + new String(decryptString));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
