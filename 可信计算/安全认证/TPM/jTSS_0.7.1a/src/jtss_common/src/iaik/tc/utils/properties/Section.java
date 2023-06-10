/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.properties;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

/**
 * One Section in Properties.
 */
public class Section {
  Hashtable properties_;
  String name_;
  StringTokenizer token_;

  public Section(String name) {
    name_ = name;
    properties_ = new Hashtable();

  }

  
  protected void addEntry(String entry) {
    token_ = new StringTokenizer(entry, "=");

    String property = token_.nextToken();
    String value;
try{
    value = token_.nextToken();}
catch (NoSuchElementException e)
{
	value="";
}
    String trimmedProp=property.trim();
    String trimmedVal=value.trim();
    
    properties_.put(trimmedProp, trimmedVal);
  }
  
  protected void addEntry(String key, String value) {
	 String trimmedProp=key.trim();
	 String trimmedVal=value.trim();
	 properties_.put(trimmedProp, trimmedVal);
	 //properties_.put(key, value);    
  }
  

  protected String getValue(String property) {
    return (String) properties_.get(property);
  }
  

  public String toString() {
    StringBuffer buf = new StringBuffer();
    buf.append("[" + name_ + "]\n");

    Iterator it = properties_.keySet().iterator();

    while (it.hasNext()) {
      String key = (String) it.next();
      buf.append(key + "=" + properties_.get(key));
      buf.append("\n");
    }

    buf.append("\n");
    return buf.toString();
  }
}
