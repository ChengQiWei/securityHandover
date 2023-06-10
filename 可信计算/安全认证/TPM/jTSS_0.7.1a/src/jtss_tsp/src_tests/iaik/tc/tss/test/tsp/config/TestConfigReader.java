/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 */


package iaik.tc.tss.test.tsp.config;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Vector;

public class TestConfigReader {
    
    public static final String COMMENT = "#";
    
    public static Vector<String> getTestClassesAsStrings(String file) throws IOException{
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
        Vector<String> classes = new Vector<String>();
        
        String line;
        while ((line = reader.readLine()) != null) {
            
            line = line.trim();
            
            // ignore empty lines and comments
            if (line.length() > 0) {
                if (line.startsWith(COMMENT)) {
                    continue;
                }
            } else {
                continue;
            }
            
            classes.addElement(line);
            
        }
        
        return classes;      
        
    }
    

}
