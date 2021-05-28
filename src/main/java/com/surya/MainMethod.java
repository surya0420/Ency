package com.surya;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.Properties;

public class MainMethod {

    public static void main(String[] args) {
//        Properties properties = new Properties();
//        try(InputStream inputStreamIO = PropUtils.class.getClassLoader().getResourceAsStream("applicationCSOB.properties")) {
//            properties.load(inputStreamIO);
//            JSONObject jsonObject = new JSONObject();
//            JSONArray jsonArray = new JSONArray();
//
//            for (String s:properties.stringPropertyNames()){
//                    JSONObject childJsonObject = new JSONObject();
//                System.out.println(s);
//                jsonObject.put("azure_backOffice_"+s, properties.getProperty(s));
//                childJsonObject.put("propname",s);
//                childJsonObject.put("propvalue","azure_backOffice_"+s);
//                jsonArray.put(childJsonObject);
//                //jsonObject.put(s, properties.getProperty(s));
//            }


//            JSONObject jsonObject1 = new JSONObject();
//            jsonObject1.put("new", new JSONArray("[\n" +
//                    "{\n" +
//                    "\"appId\": \"Admin\",\n" +
//                    "\"userId\": \"admintest\",\n" +
//                    "\"userName\": \"admintestU\"\n" +
//                    "}\n" +
//                    "]"));
//        JSONArray modify =   jsonObject1.getJSONArray("new");
//       // JSONObject jsonObject3 =
//        System.out.println( new JSONObject(modify.get(0).toString()).getString("userId"));
//            System.out.println(jsonObject1);
//
//        LinkedList<Integer>

//
//
//            System.out.println(jsonObject.toString());
//            System.out.println("properties" + jsonArray.toString().replaceAll("\\s", ""));
//
//           System.out.println(jsonObject.toString());
//        }catch (Exception e){
//
//        }

        System.out.println(getFormattedDate(new Date()));
        System.out.println(getYesterdayDate(getFormattedDate(new Date())));


        JSONObject jsonObject1 = new JSONObject();
        jsonObject1.put("jsonObject1","jsonObject1");
        jsonObject1.put("surya","surya");

        JSONObject finalJSON = new JSONObject();


        System.out.println(jsonObject1);
        System.out.println(new JSONObject().put("json", jsonObject1));

    }
    public static Date getYesterdayDate(Date presentDate){
        Calendar cal = Calendar.getInstance();
        cal.setTime(presentDate);
        cal.add(Calendar.DATE, -1);
        return cal.getTime();
    }
    private static Date getFormattedDate(Date date) {
        Date simpleDate = null;
        try{
            SimpleDateFormat formatter = new SimpleDateFormat();
            simpleDate =formatter.parse(formatter.format(date));
        }catch (Exception e){
            e.printStackTrace();
        }
        return simpleDate;
    }
    }

