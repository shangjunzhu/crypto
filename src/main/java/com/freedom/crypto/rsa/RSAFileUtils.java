package com.freedom.crypto.rsa;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import org.apache.commons.io.FileUtils;

public class RSAFileUtils {
	/**
	 * 默认线程数
	 */
	public static int DEF_BLOCK_SIZE = 6;
	/**
	 * 默认header大小
	 */
	public static int DEF_HEADER_SIZE = 4;
	
	/***** ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓  常规/单线程  公钥加密/私钥解密文件  ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ *****/
	/**
	 * 加密文件
	 * @param publicKey		公钥
	 * @param sourcePath
	 * @param destPath
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	public static void encryptFile(String publicKey, File sourceFile, File destFile)
			throws IOException, GeneralSecurityException {
		Cipher cipher = RSAUtils.getEncryptCipher(publicKey);
		convertFile(cipher, RSAUtils.MAX_ENCRYPT_BLOCK, sourceFile, destFile);
	}
	
	/**
	 * 解密文件
	 * @param privateKey
	 * @param sourcePath
	 * @param destPath
	 * @throws IOException 
	 * @throws GeneralSecurityException 
	 * @throws  
	 */
	public static void decryptFile(String privateKey, File sourceFile, File destFile) throws GeneralSecurityException, IOException {
		Cipher cipher = RSAUtils.getDecryptCipher(privateKey);
		convertFile(cipher, RSAUtils.MAX_DECRYPT_BLOCK, sourceFile, destFile);
	}
	
	/**
	 * 
	 * @param cipher
	 * @param block
	 * @param sourceFile
	 * @param destFile
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static void convertFile(Cipher cipher, int block, File sourceFile, File destFile)
			throws IOException, GeneralSecurityException {
		//
		FileInputStream input = FileUtils.openInputStream(sourceFile);
		//
		OutputStream output = FileUtils.openOutputStream(destFile);

		byte[] cache = new byte[block];
		while (input.read(cache) != -1) {
			output.write(cipher.doFinal(cache));
		}
		output.flush();
		output.close();
		input.close();
	}
	
	/***** ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑  常规/单线程  公钥加密/私钥解密文件  ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ *****/
	
	
	
	/***** ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓  多线程  公钥加密/私钥解密文件  ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ *****/
	/**
	 * 加密文件
	 * @param publicKey
	 * @param sourcePath
	 * @param destPath
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	public static void encryptFastFile(int size, String publicKey, File sourceFile, File destFile)
			throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
		// 输入流
		FileInputStream input = FileUtils.openInputStream(sourceFile);
		// 输出流
		BufferedOutputStream output = new BufferedOutputStream(FileUtils.openOutputStream(destFile));
		// 写入长度
		output.write(ByteBuffer.allocate(DEF_HEADER_SIZE).putInt(size).array());
		
		// 私钥处理
		KeyFactory keyFactory = RSAUtils.getKeyFactory();
		Key privKey = RSAUtils.getPublicKey(publicKey);
		// Cipher 数组
		Cipher[] ciphers = new Cipher[size];
		for (int i = 0; i < size; i++) {
			ciphers[i] = Cipher.getInstance(keyFactory.getAlgorithm());
			ciphers[i].init(Cipher.ENCRYPT_MODE, privKey);
		}
		convertFastFile(size, RSAUtils.MAX_ENCRYPT_BLOCK, ciphers, input, output);
	}
	
	
	
	/**
	 * 解密文件
	 * @param privateKey
	 * @param sourcePath
	 * @param destPath
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 * @throws ExecutionException 
	 * @throws InterruptedException 
	 */
	public static void decryptFastFile(String privateKey, File sourceFile, File destFile)
			throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
		// 输入流
		FileInputStream input = FileUtils.openInputStream(sourceFile);
		// 输出流
		BufferedOutputStream output = new BufferedOutputStream(FileUtils.openOutputStream(destFile));
//		OutputStream output = FileUtils.openOutputStream(FileUtils.getFile(destPath));
		byte[] header = new byte[DEF_HEADER_SIZE];
		input.read(header);
		// 线程数
		int size = ByteBuffer.wrap(header).getInt();
		// 私钥处理
		KeyFactory keyFactory = RSAUtils.getKeyFactory();
		Key privKey = RSAUtils.getPrivateKey(privateKey);
		// Cipher 数组
		Cipher[] ciphers = new Cipher[size];
		for (int i = 0; i < size; i++) {
			ciphers[i] = Cipher.getInstance(keyFactory.getAlgorithm());
			ciphers[i].init(Cipher.DECRYPT_MODE, privKey);
		}
		convertFastFile(size, RSAUtils.MAX_DECRYPT_BLOCK, ciphers, input, output);
	}
	
	/**
	 * 
	 * @param size
	 * @param blockSize
	 * @param cipher
	 * @param sourcePath
	 * @param destPath
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException 
	 */
	public static void convertFastFile(int size, int blockSize, Cipher[] ciphers, InputStream input, OutputStream output)
			throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
		// 线程池
		ExecutorService executor = new ThreadPoolExecutor(size, size, 10, TimeUnit.SECONDS,
				new ArrayBlockingQueue<>(size));
		try {
			convertFastFile(executor, size, blockSize, ciphers, input, output);
		} catch (Exception e) {
		}
		executor.shutdown();
	}
	
	
	/**
	 * 
	 * @param executor		线程池
	 * @param cipher		
	 * @param block			
	 * @param sourcePath
	 * @param destPath
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException 
	 */
	public static void convertFastFile(ExecutorService executor, int size, int blockSize, Cipher[] ciphers, InputStream input, OutputStream output)
			throws GeneralSecurityException, IOException, InterruptedException, ExecutionException {
		try {
			// 用于读取流
			byte[] cache = new byte[blockSize * size];
			// task 列表
			List<Callable<byte[]>> tasks = new ArrayList<>(size);
			// 读取到的长度
			int readLen;
			while ((readLen = input.read(cache)) != -1) {
				for (int i = 0; i < size; i++) {
					final int j = i;
					final int rLen = readLen;
					final int offset = j * blockSize;
					if(rLen > offset) {
						tasks.add(new Callable<byte[]>() {
							@Override
							public byte[] call() throws Exception {
								int len = rLen - offset > blockSize ? blockSize : rLen - offset;
								try {
									return ciphers[j].doFinal(cache, offset, len);
								} catch (Exception e) {
									System.out.println(Thread.currentThread().getId() + "] j : " + j + "  offset:" + offset
											+ " len :" + len + "  e: " + e.getMessage());
								}
								return null;
							}
						});
					}
				}
				List<Future<byte[]>> futures = executor.invokeAll(tasks);
				for (Future<byte[]> future : futures) {
					byte[] b = future.get();
					if (b != null)
						output.write(b);
					else {
						System.out.println(" readLen : " + readLen + " null null");
					}
				}
				tasks.clear();
			}
			output.flush();

		} catch (Exception e) {
		} finally {
			if (executor != null) {
				executor.shutdown();
			}
			if (output != null) {
				output.close();
			}
			if (input != null) {
				input.close();
			}
		}
	}
	/***** ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑  多线程  公钥加密/私钥解密文件  ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑ *****/
	
}
