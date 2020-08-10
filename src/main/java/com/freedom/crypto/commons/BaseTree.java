package com.freedom.crypto.commons;

import java.util.Collection;

public abstract class BaseTree<K, T> implements ITree<K, T> {

	private Collection<T> children;

	public Collection<T> getChildren() {
		return children;
	}

	public void setChildren(Collection<T> children) {
		this.children = children;
	}

}
