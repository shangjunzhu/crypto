package com.freedom.crypto.rsa;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutionException;

import org.junit.Test;

public class RSAFileUtilsTest {

	public static String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDHKz/ClB0QgQKVWkfmH64jRnjOA7VBFfJK6vmQVuvxoR0NOyDi7tfOSmGKirvbYMX9pNmUAceu8W26vkPx7FJAb9BwujkCW29Tu89C8Z/Sc1yUo2JuYq6SzTOWaNROaWNe4oEBFEN/POvxIclBb4ykIOh/1lZ1zxh2pVIo1AkuwIDAQAB";
	public static String privKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIMcrP8KUHRCBApVaR+YfriNGeM4DtUEV8krq+ZBW6/GhHQ07IOLu185KYYqKu9tgxf2k2ZQBx67xbbq+Q/HsUkBv0HC6OQJbb1O7z0Lxn9JzXJSjYm5irpLNM5Zo1E5pY17igQEUQ3886/EhyUFvjKQg6H/WVnXPGHalUijUCS7AgMBAAECgYAeC3IxN4HcQkx+ubfPP7i6PctS4EO12LrtJI7NwuhpzUoI/x+7vUeAuK6lSgBwwV2rHhwE9A3NoyXZltrgHNipF7fXQMD55MGaSb9umNTLXITT6tRC/fig84+kQW7p4MSCMBn7pT7oe2HmkFZRacqWKGvbAKLaY3LtoXVwDTnd4QJBAM0Hm75kXpv1EzZZJ5qE+tqFFTg13/MIEBHGK5B+j/bLguwdOWn7bUPzkPyE6j1ngucJN200L55mjAB9hS19WDMCQQCjtNYcprRyFRjFZ9CAx0I0b5i8hFyEncCwIcK2RUG6EPtg9D6zYgrHe7TIrO9EGBfmQ8alaOxW0G4rlu/E4plZAkAXp34PbDMCGTc7OPP5vsfWOC5niseomVCJTGywQfnIBli3dvOtx4Umps4eZBNGPE/86bJMVg38X2ZdlB2uTtzDAkBvC5CdeLs4E3VtGoGFiSQwe26ImeREFNoK36u7hfkSpMhPuP37Iksbi59S7HOUph84E8tgkm6WaOYCbW0RCYBpAkAlmFfKbFhCrMMpYy1Yiz1CS+OogGkMyjI41gYyHwa96E+XAMHrtM9wotIa6Tt5XLvJZz456Av3DEeLy/Eg5FZJ";

	@Test
	public void testEncryptFile()
			throws IOException, GeneralSecurityException, InterruptedException, ExecutionException {
		testEncrypt("normal", false);
	}

	@Test
	public void testEncryptFastFile()
			throws IOException, GeneralSecurityException, InterruptedException, ExecutionException {
		testEncrypt("Fast", true);
	}

	public void testEncrypt(String name, boolean isFast)
			throws IOException, GeneralSecurityException, InterruptedException, ExecutionException {
//		String basePath = RSAFileUtilsTest.class.getResource("/").getPath();
		String basePath = "C:\\Users\\Administrator\\Downloads\\";
		
		String sourcePath = "test01.jpg";
		String destPath = "/test011111.jpg.enc";
		String decPath = "/test011111.jpg";
//		
		System.out.println(basePath);
		
		
		File sourceFile = new File(basePath + sourcePath);
		File destFile = new File(basePath + destPath);
		File decFile = new File(basePath + decPath);

		System.out.println("[ " + name + " ] Start Time ：" + System.currentTimeMillis());
		if (isFast) {
			// 获取线程数
			int size = Runtime.getRuntime().availableProcessors();
			RSAFileUtils.encryptFastFile(size, pubKey, sourceFile, destFile);
		} else {
			RSAFileUtils.encryptFile(pubKey, sourceFile, destFile);
		}
		System.out.println("[ " + name + " ] Temp Time ：" + System.currentTimeMillis());

		if (isFast) {
			RSAFileUtils.decryptFastFile(privKey, destFile, decFile);
		} else {
			RSAFileUtils.decryptFile(privKey, destFile, decFile);
		}
		System.out.println("[ " + name + " ] End Time ：" + System.currentTimeMillis());
	}
}
