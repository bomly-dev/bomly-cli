package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;

class App {
    void load(String className) throws Exception {
        Class.forName(className);
        LogManager.getLogger(App.class).info(new ObjectMapper().toString());
    }
}
