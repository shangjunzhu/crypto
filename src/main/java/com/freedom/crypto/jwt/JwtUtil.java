package com.freedom.crypto.jwt;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

public class JwtUtil {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
	
	/**
	 * 默认有效时间 7 天
	 */
	public static long expirition = 7 * 24 * 60 * 60 * 1000;
	/**
	 * 私钥
	 */
	public static String secretKey = "p61Kf0JQyoOn7X5VFo0NstQXfSLrkLxI";

	/**
	 * 生成 token
	 * @param username
	 * @param map
	 * @return
	 */
	public static String generateJwt(String username, Map<String, Object> map) {
		return generateJwt(null, username, map);
	}
	
	/**
	 * 生成 token
	 * 
	 * @param username
	 * @param role
	 * @return
	 */
	public static String generateJwt(String subject, String username, Map<String, Object> map) {
		return generateJwt(secretKey, subject, username, map);
	}

	/**
	 * 生成 token
	 * @param secretKey
	 * @param subject
	 * @param username
	 * @param map
	 * @return
	 */
	public static String generateJwt(String secretKey, String subject, String username, Map<String, Object> map) {
		JwtBuilder builder = Jwts.builder();
		if (subject != null && !subject.isEmpty()) {
			if (map == null) {
				map = new HashMap<String, Object>();
			}
			map.put(Claims.SUBJECT, subject);
		}
		if (map != null) {
			builder.setClaims(map);
		}
		
		String token = builder.setHeaderParam("type", "JWT")
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + expirition))
				.claim("username", username)
				.signWith(SignatureAlgorithm.HS512, secretKey).compact();
		return token;
	}
	
	
	/**
	 * 解密 token
	 * @param token
	 * @return
	 */
	public static Claims decode(String token) {
		return decode(null, token);
	}
	
	/**
	 * 解密 token
	 * @param subject
	 * @param token
	 * @return
	 */
	public static Claims decode(String subject, String token) {
		JwtParser parser = Jwts.parser();
		if (subject != null && !subject.isEmpty()) {
			parser.requireSubject(subject);
		}
		return parser.setSigningKey(secretKey).parseClaimsJws(token).getBody();
	}
	
	
	public static Claims decode(String secretKey, String subject, String token) {
		JwtParser parser = Jwts.parser();
		if (subject != null && !subject.isEmpty()) {
			parser.requireSubject(subject);
		}
		return parser.setSigningKey(secretKey).parseClaimsJws(token).getBody();
	}
	
	
	/**
	 * 
	 * @param token
	 * @return
	 */
	public static boolean validateToken(String token) {
		return validateToken(secretKey, null, token);
	}
	
	
	/**
	 * 验证token
	 * @param subject
	 * @param token
	 * @return
	 */
	public static boolean validateToken(String subject, String token) {
		return validateToken(secretKey, subject, token);
	}
	
	
	/**
	 * 验证token 主题必须一致
	 * @param subject 主题
	 * @param token	
	 * @return
	 */
	public static boolean validateToken(String secretKey, String subject, String token) {
		try {
			decode(subject, token);
			return true;
		} catch (SignatureException ex) {
			logger.error("Invalid JWT signature");
		} catch (MalformedJwtException ex) {
			logger.error("Invalid JWT token");
		} catch (ExpiredJwtException ex) {
			logger.error("Expired JWT token");
		} catch (UnsupportedJwtException ex) {
			logger.error("Unsupported JWT token");
		} catch (IllegalArgumentException ex) {
			logger.error("JWT claims string is empty.");
		}
		return false;
	}

}
