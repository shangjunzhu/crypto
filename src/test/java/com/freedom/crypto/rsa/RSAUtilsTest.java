package com.freedom.crypto.rsa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Map;

import org.junit.Test;

import com.freedom.crypto.rsa.RSAUtils;

public class RSAUtilsTest {
	public static String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDHKz/ClB0QgQKVWkfmH64jRnjOA7VBFfJK6vmQVuvxoR0NOyDi7tfOSmGKirvbYMX9pNmUAceu8W26vkPx7FJAb9BwujkCW29Tu89C8Z/Sc1yUo2JuYq6SzTOWaNROaWNe4oEBFEN/POvxIclBb4ykIOh/1lZ1zxh2pVIo1AkuwIDAQAB";
	public static String privKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIMcrP8KUHRCBApVaR+YfriNGeM4DtUEV8krq+ZBW6/GhHQ07IOLu185KYYqKu9tgxf2k2ZQBx67xbbq+Q/HsUkBv0HC6OQJbb1O7z0Lxn9JzXJSjYm5irpLNM5Zo1E5pY17igQEUQ3886/EhyUFvjKQg6H/WVnXPGHalUijUCS7AgMBAAECgYAeC3IxN4HcQkx+ubfPP7i6PctS4EO12LrtJI7NwuhpzUoI/x+7vUeAuK6lSgBwwV2rHhwE9A3NoyXZltrgHNipF7fXQMD55MGaSb9umNTLXITT6tRC/fig84+kQW7p4MSCMBn7pT7oe2HmkFZRacqWKGvbAKLaY3LtoXVwDTnd4QJBAM0Hm75kXpv1EzZZJ5qE+tqFFTg13/MIEBHGK5B+j/bLguwdOWn7bUPzkPyE6j1ngucJN200L55mjAB9hS19WDMCQQCjtNYcprRyFRjFZ9CAx0I0b5i8hFyEncCwIcK2RUG6EPtg9D6zYgrHe7TIrO9EGBfmQ8alaOxW0G4rlu/E4plZAkAXp34PbDMCGTc7OPP5vsfWOC5niseomVCJTGywQfnIBli3dvOtx4Umps4eZBNGPE/86bJMVg38X2ZdlB2uTtzDAkBvC5CdeLs4E3VtGoGFiSQwe26ImeREFNoK36u7hfkSpMhPuP37Iksbi59S7HOUph84E8tgkm6WaOYCbW0RCYBpAkAlmFfKbFhCrMMpYy1Yiz1CS+OogGkMyjI41gYyHwa96E+XAMHrtM9wotIa6Tt5XLvJZz456Av3DEeLy/Eg5FZJ";

	/**
	 * 生成秘钥对
	 * 
	 * @throws Exception
	 */
	@Test
	public void testGenKeyPair() throws Exception {
		Map<String, String> keyMap = RSAUtils.genKeyPair();
		assertNotNull(keyMap);
		String pubKey = RSAUtils.getPublicKey(keyMap);
		String privKey = RSAUtils.getPrivateKey(keyMap);
		assertNotNull(pubKey);
		assertNotNull(privKey);
	}

	/**
	 * 公钥加密 与 私钥解密
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEncrypt() throws Exception {
		String message = "中国，是以华夏文明为源泉、中华文化为基础，并以汉族为主体民族的多民族国家，通用汉语、汉字，汉族与少数民族被统称为“中华民族”，又自称为炎黄子孙、龙的传人。\r\n"
				+ "中国是世界四大文明古国之一，有着悠久的历史，距今约5000年前，以中原地区为中心开始出现聚落组织进而形成国家，后历经多次民族交融和朝代更迭，直至形成多民族国家的大一统局面。20世纪初辛亥革命后，君主政体退出历史舞台，共和政体建立。1949年中华人民共和国成立后，在中国大陆建立了人民代表大会制度的政体。";
		String encStr = RSAUtils.encryptByPublicKey(message, pubKey);
		System.out.println("encStr : " + encStr);
		String decStr = RSAUtils.decryptByPrivateKey(encStr, privKey);
		System.out.println("encStr : " + encStr);
		assertEquals(message, decStr);
	}

	/**
	 * 签名与验证签名
	 * 
	 * @throws Exception
	 */
	@Test
	public void sign() throws Exception {
		String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCDHKz/ClB0QgQKVWkfmH64jRnjOA7VBFfJK6vmQVuvxoR0NOyDi7tfOSmGKirvbYMX9pNmUAceu8W26vkPx7FJAb9BwujkCW29Tu89C8Z/Sc1yUo2JuYq6SzTOWaNROaWNe4oEBFEN/POvxIclBb4ykIOh/1lZ1zxh2pVIo1AkuwIDAQAB";
		String privKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIMcrP8KUHRCBApVaR+YfriNGeM4DtUEV8krq+ZBW6/GhHQ07IOLu185KYYqKu9tgxf2k2ZQBx67xbbq+Q/HsUkBv0HC6OQJbb1O7z0Lxn9JzXJSjYm5irpLNM5Zo1E5pY17igQEUQ3886/EhyUFvjKQg6H/WVnXPGHalUijUCS7AgMBAAECgYAeC3IxN4HcQkx+ubfPP7i6PctS4EO12LrtJI7NwuhpzUoI/x+7vUeAuK6lSgBwwV2rHhwE9A3NoyXZltrgHNipF7fXQMD55MGaSb9umNTLXITT6tRC/fig84+kQW7p4MSCMBn7pT7oe2HmkFZRacqWKGvbAKLaY3LtoXVwDTnd4QJBAM0Hm75kXpv1EzZZJ5qE+tqFFTg13/MIEBHGK5B+j/bLguwdOWn7bUPzkPyE6j1ngucJN200L55mjAB9hS19WDMCQQCjtNYcprRyFRjFZ9CAx0I0b5i8hFyEncCwIcK2RUG6EPtg9D6zYgrHe7TIrO9EGBfmQ8alaOxW0G4rlu/E4plZAkAXp34PbDMCGTc7OPP5vsfWOC5niseomVCJTGywQfnIBli3dvOtx4Umps4eZBNGPE/86bJMVg38X2ZdlB2uTtzDAkBvC5CdeLs4E3VtGoGFiSQwe26ImeREFNoK36u7hfkSpMhPuP37Iksbi59S7HOUph84E8tgkm6WaOYCbW0RCYBpAkAlmFfKbFhCrMMpYy1Yiz1CS+OogGkMyjI41gYyHwa96E+XAMHrtM9wotIa6Tt5XLvJZz456Av3DEeLy/Eg5FZJ";
		String message = "中国，是以华夏文明为源泉、中华文化为基础，并以汉族为主体民族的多民族国家，通用汉语、汉字，汉族与少数民族被统称为“中华民族”，又自称为炎黄子孙、龙的传人。\r\n"
				+ "中国是世界四大文明古国之一，有着悠久的历史，距今约5000年前，以中原地区为中心开始出现聚落组织进而形成国家，后历经多次民族交融和朝代更迭，直至形成多民族国家的大一统局面。20世纪初辛亥革命后，君主政体退出历史舞台，共和政体建立。1949年中华人民共和国成立后，在中国大陆建立了人民代表大会制度的政体。";
		String signStr = RSAUtils.sign(message, privKey);
		System.out.println(signStr);

		boolean result = RSAUtils.verify(message, pubKey, signStr);
		assertEquals(result, true);
	}

}
