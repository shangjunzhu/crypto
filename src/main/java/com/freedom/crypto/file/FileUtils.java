package com.freedom.crypto.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 文件操作工具类
 * @author zhushangjun
 */
public class FileUtils extends org.apache.commons.io.FileUtils {
	/**
	 * 
	 */
	private static int BUF_SIZE = 1024;

	/**
	 * 分割文件
	 * 
	 * @param file    原文件
	 * @param maxSize 片大小（ K的整数倍）
	 * @param path    输出文件夹路径
	 * @throws IOException
	 */
	public static List<File> splitFile(File file, long maxSize, String folderPath) throws IOException {
		if (file == null || !file.exists() || file.isDirectory() || file.length() == 0) {
			throw new IllegalArgumentException("文件不存在或是文件夹");
		}
		// 分割数量
		int num = new Double(Math.ceil(file.length() * 1.0 / maxSize)).intValue();

		String name = file.getName();

		List<File> destFileList = new ArrayList<File>();
		FileInputStream input = openInputStream(file);
		for (int i = 0; i < num; i++) {
			String tname = name + "." + i;
			File tfile = new File(folderPath + File.separator + tname);

			FileOutputStream output = openOutputStream(tfile);

			byte[] buf = new byte[BUF_SIZE];
			int j = 1;
			int len = 0;
			while (j * BUF_SIZE <= maxSize && (len = input.read(buf)) != -1) {
				output.write(buf, 0, len);
				j++;
			}
			output.flush();
			output.close();
			destFileList.add(tfile);
		}
		input.close();
		return destFileList;
	}

	/**
	 * 合并文件
	 * 
	 * @param fileList 文件列表
	 * @param destFile 目标文件
	 * @return
	 * @throws IOException
	 */
	public static File mergeFile(List<File> fileList, File destFile) throws IOException {
		FileOutputStream output = openOutputStream(destFile);
		for (File file : fileList) {
			FileInputStream input = openInputStream(file);

			byte[] buf = new byte[BUF_SIZE];
			while (input.read(buf) != -1) {
				output.write(buf);
			}
			input.close();
		}
		output.flush();
		output.close();
		return destFile;
	}

	/**
	 * 分割
	 * 
	 * @param args
	 */

	public static void main(String[] args) {
		File file = new File("C:\\Users\\Administrator\\Desktop\\mysql-server.tar");
		File destFile = new File("C:\\Users\\Administrator\\Desktop\\temp\\temp\\mysql-server.tar");

		try {
			List<File> l = splitFile(file, 4 * 1024 * 1024, "C:\\Users\\Administrator\\Desktop\\temp\\temp");
			mergeFile(l, destFile);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
