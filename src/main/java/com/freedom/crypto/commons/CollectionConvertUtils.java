package com.freedom.crypto.commons;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * 集合转换工具
 * 
 * @author zhushangjun
 *
 */
public class CollectionConvertUtils {
	
	/**
	 * 将集合转换为 map
	 * @param <K>
	 * @param <T>
	 * @param coll
	 * @return
	 */
	public static <K, T extends ITree<K, T>> Map<K, List<T>> convert2Map(Collection<T> coll) {
		return convert2Map(coll, o -> o.getPKey());
	}

	/**
	 * 将集合转换为 map
	 * @param <K>
	 * @param <T>
	 * @param coll
	 * @param fun
	 * @return
	 */
	public static <K, T> Map<K, List<T>> convert2Map(Collection<T> coll, Function<T, K> fun) {
		return convert2Map(coll, fun, null);
	}
	
	/**
	 * 将集合转换为 map
	 * @param <K>
	 * @param <T>
	 * @param coll
	 * @param fun
	 * @return
	 */
	public static <K, T> Map<K, List<T>> convert2Map(Collection<T> coll, Function<T, K> fun, Predicate<? super T> predicate) {
		if (coll == null || coll.size() < 1) {
			return null;
		}
		Map<K, List<T>> m = new HashMap<K, List<T>>();
		List<T> c = null;
		for (T o : coll) {
			if(predicate != null && predicate.test(o)) {
				K k = fun.apply(o);
				c = m.get(k);
				if (c == null) {
					c = new ArrayList<>();
					m.put(k, c);
				}
				c.add(o);
			}
		}
		return m;
	}

	
	
	/**
	 * 将集合转换为 tree
	 * @param <K>
	 * @param <T>
	 * @param list
	 * @param rootId
	 * @return
	 */
	public static <K, T extends ITree<K, T>> T convert2Tree(Collection<T> list, K rootId) {
		RootHolder<T> holder = new RootHolder<>();
		Function<T, K> callback = (T o) -> {
			K k = o.getKey();
			if (k != null && k.equals(rootId)) {
				holder.setRoot(o);
			}
			return o.getPKey();
		};
		Map<K, List<T>> map = convert2Map(list, callback);

		T root = holder.getRoot();
		if(root == null) {
			throw new IllegalArgumentException("root Id 不存在");
		}
		root.setChildren(map.get(root.getKey()));
		
		build2Tree(root.getChildren(), map);
		return root;
	}

	private static <K, T extends ITree<K, T>> void build2Tree(Collection<T> list, Map<K, List<T>> tmpMap) {
		for (T t : list) {
			List<T> children = tmpMap.get(t.getKey());
			if (children != null && children.size() > 0) {
				t.setChildren(children);
				build2Tree(children, tmpMap);
			}
		}
	}
}
