/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.properties;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

/**
 * Class for handling configuration files in Java properties like formatting. 
 * <p>
 * Example of expected format:
 * <pre>
 * # a comment
 * [Section1]
 * something = anything
 * 
 * [Section2]
 * whatever = new thing
 * </pre>
 */
public class Properties {

  Hashtable sections_;

  private String sectionPointer_;

  /* Indicate a comment. */
  protected final static Set SKIP = new HashSet(Arrays.asList(new String[] { ";", "#", "" }));

  
  /**
   * Creates new empty Properties.
   */
  public Properties() {
    sections_ = new Hashtable();
  }

  
  /**
   * Creates new Properties object from file content.  
   * <p>
   * A new Properties object is created and its initial content read from indicated file. 
   */
  public Properties(String file) throws IOException {
    sections_ = new Hashtable();
    readPropertiesFile(file);
  }

  
  private void readPropertiesFile(String file) throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
    Section sec = null;

    String line;
    while ((line = reader.readLine()) != null) {

      // format line            
      line = line.trim();

      // skip comments
      if (line.length() > 0) {
        if (SKIP.contains(line.substring(0, 1))) {
          continue;
        }
      } else if (line.length()==0) {  // ignore empty line
        continue;
      }

      // read section
      if (line.startsWith("[") && line.endsWith("]")) {
        String section = line.substring(1, line.length() - 1);
        sec = new Section(section);
        sections_.put(section, sec);

      } else {
        if (isKey(line)) { // we have key with value
          if (sec == null) {
            throw new IOException("Properties must start with a section!" + line);
          }
          sec.addEntry(line);
        } else {
          System.out.println(line);
          System.out.println(line.length());
          throw new IOException("Property format error! " + line);
        }
      }
    }

    reader.close();
  }

  /**
   * Sets current section pointer.
   * 
   * @throws IllegalArgumentException if section does not exist
   */
  public synchronized void setSectionPointer(String section) {
    sectionPointer_ = section;
    if (sections_.get(section)==null) {
      throw new IllegalArgumentException("Cannot find section '"+section+"' in properties");
    }
  }
  
  /**
   * Adds a new empty section.
   * <p>
   * After successful creation of the new section the current section pointer is updated to
   * the new section.
   * If a section of the specified name already existed, the current section pointer is
   * only updated to this section. 
   * 
   * @param sectionname name of the section to create
   */
  public synchronized void addSection(String sectionname) {
    try {
      setSectionPointer(sectionname);
    } catch (IllegalArgumentException e) {
      Section sec = new Section(sectionname);
      sections_.put(sectionname, sec);
      setSectionPointer(sectionname);
    }    
  }
  
  /**
   * Determines if a section of supplied name already exists.
   * 
   * @param sectionname section name
   * @return <code>true</code> if section of that name exists,
   * <code>false</code> otherwise.
   */
  public boolean hasSection(String sectionname) {
    if (sectionname!= null) {
      if (sections_.get(sectionname)==null) {
        return false;
      } else {
        return true;
      }
    } else {
      return false;    
    }
  }
  
  /**
   * Gets array of section names.
   * 
   * @return array of section names
   */
  public synchronized ArrayList getSections() {
    ArrayList list = new ArrayList();
    Enumeration e = sections_.keys();
    while (e.hasMoreElements()) {
      list.add((String)e.nextElement());
    }
    return list;
  }
  

  
  /**
   * Sets a property in the specified section.
   * 
   * @param section section name
   * @param key property name
   * @param value property value
   * 
   * @throws IllegalArgumentException if any parameter is null or
   *   section does not exist
   */
  public synchronized void setProperty(String section, String key, String value) {
    if (section==null) {
      throw new IllegalArgumentException("section must not be null");
    }
    if (key==null) {
      throw new IllegalArgumentException("key must not be null");
    }
    if (value==null) {
      throw new IllegalArgumentException("value must not be null");
    }
    
    Section s = (Section) sections_.get(section);
    if (s==null) {
      throw new IllegalArgumentException("section "+section+" does not exits");
    }
    s.addEntry(key, value);
  }
  
  
  
  /**
   * Sets a property in the currently selected section.
   * 
   * @param key property name
   * @param value value to set
   */
  public synchronized void setProperty(String key, String value) {
    setProperty(sectionPointer_, key, value);
  }
  

  /**
   * Returns a property from the section that has been previously specified via {@link #setSectionPointer}.
   * 
   * @param key property name
   * @return property value
   */
  public synchronized String getProperty(String key) {
    return getProperty(sectionPointer_, key);
  }
  
  /**
   * Returns a property from the section that has been previously specified via {@link #setSectionPointer}.
   * It is assumed the property String can be converted on the fly to an integer type.  
   * 
   * @param key property name
   * @return property value
   */
  public synchronized int getPropertyAsInt(String key) {
    return Integer.parseInt( getProperty(sectionPointer_, key) );
  }
  
  /**
   * Returns a property from the section that has been previously specified via {@link #setSectionPointer}.
   * It is assumed the property String can be converted on the fly to a BigInteger type.  
   * 
   * @param key property name
   * @return property value
   */
  public synchronized BigInteger getPropertyAsBigInt(String key) {
    return new BigInteger( getProperty(sectionPointer_, key) );
  }

  

  /**
   * Returns a property from the specified section.
   * @param section section name
   * @param key property name
   * @return property value
   * @throws IllegalArgumentException if section does not exist
   */
  public String getProperty(String section, String key) {
    Section csection = ((Section) sections_.get(section));
    if (csection==null) {
      throw new IllegalArgumentException();
    }
    return csection.getValue(key);
//    return (String) ((Section) sections_.get(section)).getValue(key);
  }
  
  /**
   * Returns a property from the specified section.
   * It is assumed the property String can be converted on the fly to an integer type.  
   * 
   * @param section section name
   * @param key property name
   * @return property value
   * @throws IllegalArgumentException if section does not exist
   */
  public int getPropertyAsInt(String section, String key) {
    return Integer.parseInt( getProperty(section, key) );
  }
  
  /**
   * Returns a property from the specified section.
   * It is assumed the property String can be converted on the fly to a BigInteger type.  
   * 
   * @param section section name
   * @param key property name
   * @return property value
   * @throws IllegalArgumentException if section does not exist
   */
  public BigInteger getPropertyAsBigInt(String section, String key) {
    return new BigInteger( getProperty(section, key) );
  }
  
  

  /**
   * Returns whether the line is line with key and value or not.
   * @param line
   * @return
   */
  private boolean isKey(String line) {
    return (line.indexOf("=") != -1);
  }

  public String toString() {
    StringBuffer buf = new StringBuffer();
    Iterator it = sections_.keySet().iterator();

    while (it.hasNext()) {
      String key = (String) it.next();
      buf.append(((Section) sections_.get(key)).toString());
    }
    return buf.toString();
  }
}
