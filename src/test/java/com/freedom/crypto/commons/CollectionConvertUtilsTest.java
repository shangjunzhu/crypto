package com.freedom.crypto.commons;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class CollectionConvertUtilsTest {

	private List<TestData> getTestData() {
		List<TestData> list = new ArrayList<>();
		list.add(new TestData(null, 0, "name0"));
		
		list.add(new TestData(0, 1, "name1"));
		list.add(new TestData(0, 2, "name2"));
		list.add(new TestData(0, 3, "name3"));

		list.add(new TestData(1, 11, "name11"));
		list.add(new TestData(1, 12, "name12"));
		list.add(new TestData(1, 13, "name13"));

		list.add(new TestData(2, 21, "name21"));
		list.add(new TestData(2, 22, "name22"));
		list.add(new TestData(2, 23, "name23"));

		list.add(new TestData(12, 121, "name121"));
		list.add(new TestData(12, 122, "name122"));
		list.add(new TestData(12, 123, "name123"));
		return list;
	}
	
	
	@Test
	public void test2Map() throws JsonProcessingException {
		List<TestData> list = getTestData();
		ObjectMapper mapper = new ObjectMapper();
		mapper.getSerializerProvider().setNullKeySerializer(new NullKeySerializer());
		String jsonStr = mapper.writeValueAsString(CollectionConvertUtils.convert2Map(list));
		System.out.println(jsonStr);

	}
	
	@Test
	public void test2Tree() throws JsonProcessingException {
		List<TestData> list = getTestData();
		TestData testData = CollectionConvertUtils.convert2Tree(list, 1);
		
		ObjectMapper mapper = new ObjectMapper();
		String jsonStr = mapper.writeValueAsString(testData);
		System.out.println(jsonStr);
	}
	
	
	public static class NullKeySerializer extends StdSerializer<Object> {
		public NullKeySerializer() {
			this(null);
		}

		public NullKeySerializer(Class<Object> t) {
			super(t);
		}

		@Override
		public void serialize(Object nullKey, JsonGenerator jsonGenerator, SerializerProvider unused)
				throws IOException, JsonProcessingException {
			jsonGenerator.writeFieldName("");
		}
	}
	
	
	
	public static class TestData extends  BaseTree<Integer, TestData> {
		private Integer pid;
		
		private Integer id;
		
		private String name;

		public Integer getPid() {
			return pid;
		}

		public void setPid(Integer pid) {
			this.pid = pid;
		}

		public Integer getId() {
			return id;
		}

		public void setId(Integer id) {
			this.id = id;
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		@Override
		public Integer getKey() {
			return id;
		}

		public TestData(Integer pid, Integer id, String name) {
			super();
			this.pid = pid;
			this.id = id;
			this.name = name;
		}

		@Override
		public Integer getPKey() {
			return pid;
		}
	}

}
