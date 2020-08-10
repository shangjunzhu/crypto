package com.freedom.crypto.commons;

import java.util.Collection;

public interface ITree<K, T> extends IKey<K> {

	/**
	 * 转换map 对应的KEY
	 * @return
	 */
	public K getPKey();
	/**
	 * 
	 * @param coll
	 * @return
	 */
	public void setChildren(Collection<T> coll);

	/**
	 * 
	 * @return
	 */
	public Collection<T> getChildren();
}
