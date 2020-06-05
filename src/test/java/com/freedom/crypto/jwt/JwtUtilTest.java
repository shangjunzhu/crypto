package com.freedom.crypto.jwt;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtUtilTest {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtUtilTest.class);
	
	@Test
	public void testToken() {
		String subject = "abc";
		String username = "zhangshan";
		Map<String, Object> map = new HashMap<>();
		map.put("role", "ROLE_ADMIN, ROLE_USER");
		map.put("time", System.currentTimeMillis());
		/**
		 * 
		 */
		String token = JwtUtil.generateJwt(subject, username, map);
		assertNotNull(token);
		
		assertTrue(JwtUtil.validateToken(subject, token));
		
		Map<String, Object> mapData = JwtUtil.decode(subject, token);
		System.out.println("mapData : " + mapData.toString());
		assertNotNull(mapData);
//		assertEquals(mapData.get("role"), "ROLE_ADMIN, ROLE_USER");
		
		
		
	}

}
