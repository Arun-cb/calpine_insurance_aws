from django.http import JsonResponse, HttpResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status, filters
import mysql.connector as sqlConnect
from .serializers import * 
import cx_Oracle
from django.db.models import F, Q


@api_view(["POST"])
def set_db_sql_connection(request):
    reqconnData = request.data
    
    mydb = sqlConnect.connect(
    host=reqconnData.get("host_id"), 
    user=reqconnData.get("user_name"),
    password=reqconnData.get("password"),
    database=reqconnData.get("database_name"),
    )

    if mydb.is_connected():
        connect_message = "Connected"
        return Response(connect_message, status=status.HTTP_200_OK)
    else:
        error_message = "Not Connected"
        return Response(error_message,status=status.status.HTTP_400_BAD_REQUEST)
    

# Query Defnition
@api_view(["POST"])
def fnStoreQueryNameConnectionData (request):
    
    connnectionrequestdata = request.data
    
    postConnData = {
        "query_name" : connnectionrequestdata.get("query_name"),
        "connection_id" : connnectionrequestdata["savedConnectionItems"].get("id"),
        "query_text": connnectionrequestdata.get("query_name")
        if request.data.get("query_text") == None
        else request.data.get("query_text"),
        "query_status": False
        if request.data.get("query_status") == None
        else request.data.get("query_status"),
        "query_type": False
        if request.data.get("query_type") == None
        else request.data.get("query_type"),
        "created_user" : connnectionrequestdata.get("created_user"),
        "created_by" : connnectionrequestdata.get("created_by"),
        "last_updated_by" : connnectionrequestdata.get("last_updated_by")
    }
    
    queryDefnitionSerilazier = qb_defnition_serializer(data=postConnData)
    
    if queryDefnitionSerilazier.is_valid():
        queryDefnitionSerilazier.save()
        return Response(queryDefnitionSerilazier.data,status = status.HTTP_201_CREATED)
    
    return Response(queryDefnitionSerilazier.errors,status = status.HTTP_400_BAD_REQUEST)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def fnUpdateQueryNameConnectionData (request,id):
    item = query_definition.objects.get(id=id)
    
    serializer = qb_defnition_serializer(instance=item, data=request.data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors,status = status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def fnGetQueryDefinition(request,id=0):
    if id==0:
        queryDefinitionData = query_definition.objects.filter(delete_flag="N")
    else:
        queryDefinitionData = query_definition.objects.filter(id=id)
        
    definitionSerializer = qb_defnition_serializer(queryDefinitionData,many=True)
    return Response(definitionSerializer.data,status = status.HTTP_200_OK)

# ? GET Range Query Definition

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_query_definition(request, start, end, created_user, search=False):
    try:
        if not search:
            query_def_len = query_definition.objects.filter(delete_flag="N", created_user= created_user).count()
            query_def = query_definition.objects.filter(delete_flag="N", created_user= created_user)[start:end]
        else:
            query_def_len = query_definition.objects.filter(Q(query_name__icontains = search) | Q(created_by__icontains = search) | Q(created_date__icontains = search), delete_flag="N", created_user= created_user).count()
            query_def = query_definition.objects.filter(Q(query_name__icontains = search) | Q(created_by__icontains = search) | Q(created_date__icontains = search), delete_flag="N", created_user= created_user)[start:end]
        query_def_csv_export = query_definition.objects.filter(delete_flag="N", created_user= created_user)
        serializer = qb_defnition_serializer(query_def, many=True)
        serializer_csv_export = qb_defnition_serializer(query_def_csv_export, many=True)
        return Response(
            {
                "data": serializer.data,
                "data_length": query_def_len,
                "csv_data": serializer_csv_export.data,
            }
        )
        
    except Exception as e:
        return Response(f"exception:{e}",status=status.HTTP_400_BAD_REQUEST)
        
# ? Shared Query

# Query Defnition
@api_view(["POST"])
def ins_shared_query_definition (request):
    
    sharedquerydata = request.data

    if request.data.get("permission_to_edit") != None:
        for i in range(len(sharedquerydata["permission_to_edit"])):
            insshareEditData = {
            "permission_to" : sharedquerydata["permission_to_edit"][i],
            "permission_by" : sharedquerydata.get("permission_by"),
            "permission_type" : "Editable",
            "query_id" : sharedquerydata.get("query_id"),
            "created_by" : sharedquerydata.get("created_by"),
            "last_updated_by" : sharedquerydata.get("last_updated_by")
            }

            shareEditserializer = shared_query_definition_serializer(data=insshareEditData)
            if shareEditserializer.is_valid():
                shareEditserializer.save()
            else:
                return Response(shareEditserializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    if request.data.get("permission_to_view") != None:
        for i in range(len(sharedquerydata["permission_to_view"])):
            insshareViewData = {
            "permission_to" : sharedquerydata["permission_to_view"][i],
            "permission_by" : sharedquerydata.get("permission_by"),
            "permission_type" : "Read only",
            "query_id" : sharedquerydata.get("query_id"),
            "created_by" : sharedquerydata.get("created_by"),
            "last_updated_by" : sharedquerydata.get("last_updated_by")
            }

            shareViewserializer = shared_query_definition_serializer(data=insshareViewData)
            if shareViewserializer.is_valid():
                shareViewserializer.save()
            else:
                return Response(shareViewserializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(request.data, status=status.HTTP_201_CREATED)   

    # inssharedData = {
    #     "permission_to" : sharedquerydata.get("permission_to"),
    #     "permission_by" : sharedquerydata.get("permission_by"),
    #     "permission_type" : sharedquerydata.get("permission_type"),
    #     "query_id" : sharedquerydata.get("query_id"),
    #     "created_by" : sharedquerydata.get("created_by"),
    #     "last_updated_by" : sharedquerydata.get("last_updated_by")
    # }
    
    # sharedqueryDefnitionSerilazier =shared_query_definition_serializer(data=inssharedData)
    
    # if sharedqueryDefnitionSerilazier.is_valid():
    #     sharedqueryDefnitionSerilazier.save()
    #     return Response(sharedqueryDefnitionSerilazier.data,status = status.HTTP_201_CREATED)
    # else:
    #     return Response(sharedqueryDefnitionSerilazier.errors,status=status.HTTP_400_BAD_REQUEST)
    
    # return Response("sharedqueryDefnitionSerilazier.errors",status = status.HTTP_201_CREATED)

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def upd_shared_query_definition (request,id):
    item = shared_query_definition.objects.get(id=id)
    
    serializer = shared_query_definition_serializer(instance=item, data=request.data)
    
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors,status = status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def get_shared_query_definition(request,id=0):
    if id==0:
        queryDefinitionData = shared_query_definition.objects.filter(delete_flag="N")
    else:
        queryDefinitionData = shared_query_definition.objects.filter(id=id)
        
    definitionSerializer = shared_query_definition_serializer(queryDefinitionData,many=True)
    return Response(definitionSerializer.data,status = status.HTTP_200_OK)

# ? GET Range Shared Query Definition

@api_view(["GET"])
# @permission_classes([IsAuthenticated])
def get_range_shared_query_definition(request, start, end, permission_to, search=False):
    try:
        if not search:
            query_def_len = shared_query_definition.objects.filter(delete_flag="N", permission_to= permission_to).count()
            query_def = shared_query_definition.objects.filter(delete_flag="N", permission_to= permission_to)[start:end]
        else:
            query_def = shared_query_definition.objects.filter(Q(query_name__icontains = search) | Q(created_by__icontains = search) | Q(created_date__icontains = search), delete_flag="N", permission_to= permission_to)[start:end]
        serializer = shared_query_definition_serializer(query_def, many=True)
        
        # ? List Of Query Id's 
        shared_query_ids = [item['query_id'] for item in serializer.data]

        if not search:
            shared_query_def_len = query_definition.objects.filter(delete_flag="N", id__in=shared_query_ids).count()
            shared_query_def = query_definition.objects.filter(delete_flag="N", id__in=shared_query_ids)
        else:
            shared_query_def_len = query_definition.objects.filter(Q(query_name__icontains = search) | Q(created_by__icontains = search) | Q(created_date__icontains = search), delete_flag="N", id__in=shared_query_ids).count()
            shared_query_def = query_definition.objects.filter(Q(query_name__icontains = search) | Q(created_by__icontains = search) | Q(created_date__icontains = search), delete_flag="N", id__in=shared_query_ids)[start:end]
        shared_query_def_csv_export = query_definition.objects.filter(delete_flag="N", id__in=shared_query_ids)
        shared_serializer = qb_defnition_serializer(shared_query_def, many=True)

        shared_serializer_csv_export = qb_defnition_serializer(shared_query_def_csv_export, many=True)

        return Response(
            {
                "data": shared_serializer.data,
                "data_length": query_def_len,
                "csv_data": shared_serializer_csv_export.data,
                "shared_data": serializer.data,
            }
        )
        
    except Exception as e:
        return Response(f"exception:{e}",status=status.HTTP_400_BAD_REQUEST)


# Selected Table
@api_view(["POST"])
def fnsaveSelectedTables (request):
    tableRequestData = request.data
    for i in range(len(tableRequestData)):
        selectedTableData = {
            "table_name": tableRequestData[i]["table_name"],
            "table_id" : tableRequestData[i]["table_id"],
            "query_id" : tableRequestData[i]["query_id"],
            "created_by" : tableRequestData[i]["created_by"],
            "last_updated_by" : tableRequestData[i]["last_updated_by"]
        }

        id_to_update = tableRequestData[i].get("query_id")
        
        if "id" == None:
            queryTableInstance = query_definition.objects.get(id=id_to_update)
            queryTableserilizers = qb_table_serializer(instance = queryTableInstance,data=selectedTableData)
            
            if queryTableserilizers.is_valid():
                queryTableserilizers.save()
        else:
            queryTableSerilizers = qb_table_serializer(data=selectedTableData)
            
            if queryTableSerilizers.is_valid():
                queryTableSerilizers.save()
            else:
                return Response(queryTableSerilizers.errors,status = status.HTTP_400_BAD_REQUEST)
        
        
    return Response(selectedTableData,status = status.HTTP_201_CREATED)


@api_view(["GET"])
def fnGetQueryBuilderTable(request,id=0):
    
    if id==0:
            queryBuilderTable = query_builder_table.objects.filter(delete_flag = "N")
    else:
        queryBuilderTable = query_builder_table.objects.filter(query_id=id)
        
        
    builderTableSerializer = qb_table_serializer(queryBuilderTable,many=True)
    return Response(builderTableSerializer.data,status = status.HTTP_200_OK)

@api_view(["POST"])
def fnGetTableData(request):
    connnectionrequestdata = request.data
    
    saved_connection = connnectionrequestdata["savedConnectionItems"]
    
    mydb = sqlConnect.connect(
    host = saved_connection.get("host_id"), 
    user = saved_connection.get("user_name"),
    password = saved_connection.get("password"),
    database = saved_connection.get("database_name"),
    )
    
    mycursor = mydb.cursor()
    
    table_schema = saved_connection.get("database_name")
    
    query = "SELECT table_name FROM information_schema.tables WHERE table_schema = %s AND table_type = 'BASE TABLE';"
    
    mycursor.execute(query, (table_schema,))
    
    table_names = [{"table_id": idx, "table_name": table[0]} for idx, table in enumerate(mycursor.fetchall(), start=1)]

    return Response(table_names, status=status.HTTP_200_OK)


# Column Display , Insert and Get
@api_view(["POST"])
def rb_sql_show_columns(request):
    reqData = request.data
    connnectionrequestdata = reqData.get("getselectedConnections")
    reqTableColumnData = reqData.get("rightItems")
    
    saved_tables = connnectionrequestdata["savedConnectionItems"]
    
    mydb = sqlConnect.connect(
    host = saved_tables.get("host_id"), 
    user = saved_tables.get("user_name"),
    password = saved_tables.get("password"),
    database = saved_tables.get("database_name"),
    )

    allResults = []

    for table_info in reqTableColumnData:
        tableName = table_info['table_name']
        tableId = table_info['table_id']
        dbCursor = mydb.cursor()
        dbCursor.execute(f"SHOW COLUMNS FROM {tableName}")

        results = [{"id":idx,"columnName":row[0], "dataType":row[1].split('(')[0], "tableId": tableId} for idx,row in enumerate(dbCursor.fetchall(),start=1)]
        tableResults = {tableName:results}
        allResults.append(tableResults)
    
    return Response(allResults, status=status.HTTP_200_OK)


@api_view(["POST"])
def fnsaveSelectedColumn(request):
    reqColumnData = request.data
    for table_data in reqColumnData:
        for column_data in table_data["table_columns"]:
            postData={
                "table_column_query_id": table_data["query_id"],
                "column_name": column_data["columnName"],
                "alias_name": None if column_data["setAliasName"] is None else column_data["setAliasName"],
                "table_column_table_id": column_data["tableId"],
                "created_by": table_data["created_by"],
                "last_updated_by": table_data["last_updated_by"],
            }
                        
            # postcolumnserilizers = qb_table_columns_serializers(data=postData)
            
            # if postcolumnserilizers.is_valid():
            #     postcolumnserilizers.spostcolumnserilizersave()
            # else:
            #     return Response(postcolumnserilizers.errors,status=status.HTTP_400_BAD_REQUEST)
            
    return Response(postData,status=status.HTTP_200_OK)


@api_view(["GET"])
def fngetsavedcolumns(request,id=0):
    
    if id==0:
            savedcolumnsData = query_builder_table_columns.objects.filter(delete_flag = "N")
    else:
        savedcolumnsData = query_builder_table_columns.objects.filter(table_column_query_id=id)
        
    saveColumnDataSerializers = qb_table_columns_serializers(savedcolumnsData,many=True)
    return Response(saveColumnDataSerializers.data,status = status.HTTP_200_OK)

# join table post and get

@api_view(["POST"])
def fninsjointablesave(request):
    reqjointabledata = request.data
    for i in range(len(reqjointabledata)):
        listofjointabledata ={
            "join_type" : reqjointabledata[i]["selectedAttribute"],
            "join_column_name1" : reqjointabledata[i]["selectedColumn"],
            "join_column_name2" : reqjointabledata[i]["selectedColumn2"],
            "tab_join_query_id" : reqjointabledata[i]["query_id"],
            "tab_join_table_id_one" : reqjointabledata[i]["tableid1"],
            "tab_join_table_id_two" : reqjointabledata[i]["tableid2"],
            "created_by" : reqjointabledata[i]["created_by"],
            "last_updated_by" : reqjointabledata[i]["last_updated_by"]
        }
        
        joinTableDataSerializers = qb_table_joins_serializers(data = listofjointabledata)
        
        if joinTableDataSerializers.is_valid():
            joinTableDataSerializers.save()
            
    return Response(joinTableDataSerializers.data,status=status.HTTP_200_OK)   


@api_view(["GET"])
def fnGetJoinTableColumnData(request,id=0):
    
    if id==0:
        savedJoinTableColumData = query_builder_table_joins.objects.filter(delete_flag = "N")
    else:
        savedJoinTableColumData = query_builder_table_joins.objects.filter(tab_join_query_id=id)
        
    savedJoinTableSerializers = qb_table_joins_serializers(savedJoinTableColumData,many=True)
    return Response(savedJoinTableSerializers.data,status = status.HTTP_200_OK)
    

# Column Alias Post and Get
@api_view(["PUT"])
def fn_ins_column_alias(request):
    request_alias_data = request.data
    
    for column_data in request_alias_data:
        post_data = {
            "table_column_query_id": column_data["query_id"],
            "column_name": column_data["selectedColumnName"],
            "alias_name": column_data["setAliasName"],
            "table_column_table_id": column_data["aliastableId"],
            "created_by": column_data["created_by"],
            "last_updated_by": column_data["last_updated_by"],
        }

        # Filter data based on table_column_query_id
        alias_table_data = query_builder_table_columns.objects.filter(table_column_query_id=post_data["table_column_query_id"])
        

        # Convert the queryset to a list before passing it to the serializer
        alias_table_data_list = list(alias_table_data)

        # Update data using the serializer        
        alias_table_data_serializer = qb_table_columns_serializers(instance=alias_table_data_list[0], data=post_data)

        if alias_table_data_serializer.is_valid():
            alias_table_data_serializer.save()
            return Response({"message": "Data updated successfully"}, status=status.HTTP_200_OK)                
            
        else:
            return Response(alias_table_data_serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    


@api_view(["GET"])
def fn_get_column_alias(request):
    savedAliasTableColumData = query_builder_table_alias.objects.filter(delete_flag = "N")
    savedAliasTableSerializers = qb_table_alias_serializers(savedAliasTableColumData,many=True)
    return Response(savedAliasTableSerializers.data,status = status.HTTP_200_OK)



@api_view(["POST"])
def fn_ins_column_aggregate(request):
    requestAggregateData = request.data
    for i in range(len(requestAggregateData)):
        listofaggregatetabledata ={
            "agg_fun_name" : requestAggregateData[i]["selectedAttribute"],
            "table_aggragate_query_id" : requestAggregateData[i]["query_id"],
            "table_aggregate_table_id" : requestAggregateData[i]["aggregatetableId"],
            "table_aggregate_column_id" : requestAggregateData[i]["aggregatecolumnId"],
            "created_by" : requestAggregateData[i]["created_by"],
            "last_updated_by" : requestAggregateData[i]["last_updated_by"]
        }
        
        
        aggregateserializers = qb_table_aggergate_serializers(data = listofaggregatetabledata)
        
        
        if aggregateserializers.is_valid():
            aggregateserializers.save()
        else:
            return Response(aggregateserializers.errors,status=status.HTTP_400_BAD_REQUEST)
            
    return Response(aggregateserializers.data,status=status.HTTP_200_OK)
    


@api_view(["GET"])
def fn_get_column_aggregate(request,id=0):
    
    if id==0:
            savedAggregatedTableColumData = query_builder_aggeration_function_table.objects.filter(delete_flag = "N")
    else:
        savedAggregatedTableColumData = query_builder_aggeration_function_table.objects.filter(table_aggragate_query_id = id)
        
    savedAggregatedTableSerializers = qb_table_aggergate_serializers(savedAggregatedTableColumData,many=True)
    return Response(savedAggregatedTableSerializers.data,status = status.HTTP_200_OK)


# Execute Query
@api_view(["POST"])
def fnpostquerytoexecute(request):
    queryText = request.data
    
    mydb = sqlConnect.connect(
    host="localhost", 
    user="root",
    password="",
    database="score_card"
    )
    
    
    dbCursor = mydb.cursor(dictionary = True)
    dbCursor.execute(queryText)
    columns = [column[0] for column in dbCursor.description]
    results = dbCursor.fetchall()
    response_data = [{'columns':columns,'data':results}]
    return Response(response_data,status=status.HTTP_200_OK)   



@api_view(["POST"])
def set_db_oracle_connection(request):
    mydb = cx_Oracle.connect('sys/Admin123@localhost:1521/orcl',mode=cx_Oracle.SYSDBA)
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM smpletable")
    columns = [col[0] for col in mycursor.description]
    results = [dict(zip(columns, row)) for row in mycursor.fetchall()]
    return Response(results, status=status.HTTP_200_OK)


# Test API FOR QUERY EXECUTION 
@api_view(["POST"])
def fnGetQueryResult(request):
    connnectionrequestdata = request.data
    
    saved_connection = connnectionrequestdata["savedConnectionItems"]
    query = connnectionrequestdata["query_text"]
    
    mydb = sqlConnect.connect(
    host = saved_connection.get("host_id"), 
    user = saved_connection.get("user_name"),
    password = saved_connection.get("password"),
    database = saved_connection.get("database_name"),
    )

    mycursor = mydb.cursor(dictionary = True)

    try:
        # mycursor.execute(query)
        # Modify the query to include a LIMIT clause
        query_with_limit = f"{query} LIMIT 10"
        
        mycursor.execute(query_with_limit)
        columns = [column[0] for column in mycursor.description]
        results = mycursor.fetchall()
        response_data = [{'columns': columns, 'data': results}]
        
        return Response(response_data, status=status.HTTP_200_OK)
    except sqlConnect.Error as e:
        # Handle the database-related errors, including syntax errors
        error_message = str(e)
        
        return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
    finally:
        mycursor.close()
        mydb.close()




def fun_ins_upd_builder_table(data,def_query_id,created_by_id, last_updated_by_id):
    
    tableListData = []
    
    for table_data in data["Page2"]:
                            
                postTableData = {
                            "table_name": table_data["table_name"],
                            "table_id": table_data["table_id"],
                            "query_id": def_query_id,
                            "created_by": created_by_id,
                            "last_updated_by": last_updated_by_id
                        }
                
                
                if "id" in table_data and "query_id" in table_data["query_id"]:
                    dataTable = query_builder_table.objects.get(id = table_data["id"],query_id = table_data["query_id"])
                    querytableserilizer = qb_table_serializer(instance=dataTable, data=postTableData)

                    if querytableserilizer.is_valid():
                        querytableserilizer.save()
                        tableListData.append({'id':querytableserilizer.data["id"],'tb_name':querytableserilizer.data["table_name"]})
                    else:
                        return Response(querytableserilizer.errors,"err:",status = status.HTTP_400_BAD_REQUEST)
                else:
                    querytableserilizer = qb_table_serializer(data=postTableData)
                    if querytableserilizer.is_valid():
                        querytableserilizer.save()
                        tableListData.append({'id':querytableserilizer.data["id"],'tb_name':querytableserilizer.data["table_name"]})
                        
                    else:
                        return Response("errors",querytableserilizer.errors,status = status.HTTP_400_BAD_REQUEST)
                        
    fn_ins_upd_column_data(data,tableListData,def_query_id,created_by_id, last_updated_by_id)  
    

def fn_ins_upd_column_data(tabl_col_data,tableListData,def_query_id,created_by_id, last_updated_by_id):
    
        columnListId = []
    
        for column_data in tabl_col_data["Page4"]["getSelectedColumn"]:
            for col_single_data in column_data["table_columns"]:
                
                col_alias_name = find_column_alias(tabl_col_data["Page4"]["getcolumnalias"],column_data["table_name"],col_single_data["columnName"]) 
                 
                tbl_id= find_table(tableListData,column_data["table_name"])
                
                if col_alias_name is not None:
                    postColumnData={
                        "table_column_query_id": def_query_id,
                        "column_name": col_single_data["columnName"],
                        "table_column_table_id": tbl_id,
                        "alias_name": col_alias_name["setAliasName"],
                        "col_function":col_alias_name["setColumnFunction"],
                        "created_by":created_by_id,
                        "last_updated_by": last_updated_by_id
                    }
                    
                    if "id" in col_single_data:
                        columnTable = query_builder_table_columns.objects.get(id = col_single_data["id"])
                        queryColumnserilizer = qb_table_columns_serializers(instance = columnTable,data =postColumnData )
                        
                        if (queryColumnserilizer.is_valid()):
                                queryColumnserilizer.save() 
                                columnListId.append({'id':queryColumnserilizer.data["id"],"column_name":queryColumnserilizer.data["column_name"]})
                        
                    else:
                        queryColumnserilizer = qb_table_columns_serializers(data = postColumnData)
                        if (queryColumnserilizer.is_valid()):
                            queryColumnserilizer.save()
                            columnListId.append({'id':queryColumnserilizer.data["id"],"column_name":queryColumnserilizer.data["column_name"]})
                        
                else:
                    postColumnData={
                        "table_column_query_id": def_query_id,
                        "column_name": col_single_data["columnName"],
                        "table_column_table_id": tbl_id,
                        "alias_name": None,
                        "col_function":None,
                        "created_by":created_by_id,
                        "last_updated_by": last_updated_by_id
                    }
                    
                    if "id" in col_single_data:
                        columnTable = query_builder_table_columns.objects.get(id = col_single_data["id"])
                        queryColumnserilizer = qb_table_columns_serializers(instance = columnTable,data =postColumnData )
                        
                        if (queryColumnserilizer.is_valid()):
                            queryColumnserilizer.save()
                            columnListId.append({'id':queryColumnserilizer.data["id"],"column_name":queryColumnserilizer.data["column_name"]})
                        
                    else:
                        queryColumnserilizer = qb_table_columns_serializers(data = postColumnData)
                        if (queryColumnserilizer.is_valid()):
                            queryColumnserilizer.save()
                            columnListId.append({'id':queryColumnserilizer.data["id"],"column_name":queryColumnserilizer.data["column_name"]})
                            
        
        fn_ins_upd_aggreation_data(tabl_col_data,columnListId,tbl_id,def_query_id,created_by_id, last_updated_by_id,tableListData)


def fn_ins_upd_aggreation_data(agg_col_data,columnListId,tbl_id,def_query_id,created_by_id, last_updated_by_id,tableListData):
    
    for aggregatedColumnData in agg_col_data["Page5"]:
        
        columnId = findColumnId(aggregatedColumnData["selectedColumn"],columnListId)
        
        listofaggregatetabledata ={
            "agg_fun_name" : aggregatedColumnData["selectedAttribute"],
            "table_aggragate_query_id" : def_query_id,
            "table_aggregate_table_id" : tbl_id,
            "table_aggregate_column_id" : columnId,
            "created_by": created_by_id,
            "last_updated_by": last_updated_by_id
            }
        
        if "id" in aggregatedColumnData:
            
            aggregateData = query_builder_aggeration_function_table.objects.get(id= aggregatedColumnData["id"])
            queryAggregateserilizer = qb_table_aggergate_serializers(instance= aggregateData,data=listofaggregatetabledata)
            
            if queryAggregateserilizer.is_valid():
                queryAggregateserilizer.save()
        else:
            queryAggregateserilizer = qb_table_aggergate_serializers(data= listofaggregatetabledata)
            
            if queryAggregateserilizer.is_valid():
                queryAggregateserilizer.save()
                
    fn_ins_upd_join_data(agg_col_data,tbl_id,def_query_id,created_by_id, last_updated_by_id,tableListData)



def fn_ins_upd_join_data(join_col_data,tbl_id,def_query_id,created_by_id, last_updated_by_id,tableListData):
    
    
    for jointableData in join_col_data["Page6"]["getjoinrows"]:
        
        
        join_table_one = find_table(tableListData,jointableData["selectedTable"])
        join_table_two = find_table(tableListData,jointableData["selectedTable2"])
        
        listofjointabledata ={
            "join_type" : jointableData["selectedAttribute"],
            "join_column_name1" : jointableData["selectedColumn"],
            "join_column_name2" : jointableData["selectedColumn2"],
            "tab_join_query_id" : def_query_id,
            "tab_join_table_id_one" : join_table_one,
            "tab_join_table_id_two" : join_table_two,
            "created_by": created_by_id,
            "last_updated_by": last_updated_by_id
            }
        
        if "id" in jointableData:
            joinTableData = query_builder_table_joins.objects.get(id = jointableData["id"])
            joinTableDataSerializers = qb_table_joins_serializers(instance =joinTableData,data = listofjointabledata )
            
            if joinTableDataSerializers.is_valid():
                joinTableDataSerializers.save()
        else:
            joinTableDataSerializers = qb_table_joins_serializers(data= listofjointabledata)
            if joinTableDataSerializers.is_valid():
                joinTableDataSerializers.save()
            

@api_view(["PUT"])
def fn_ins_query_column_data(request):
    
    requestQueryData = request.data
    
    connection_info = requestQueryData["Page1"]["savedConnectionItems"]
    
    
    connection_query_name = requestQueryData["Page1"]["query_name"]
    
    
    # postConnData = {
    #     "query_name": connection_query_name,
    #     "connection_id": connection_info["id"],
    #     "query_text": connection_info["connection_name"],
    #     "created_by": connection_info["created_by"],
    #     "last_updated_by": connection_info["last_updated_by"]
    # }

    postConnData = {
        "query_name" : connection_query_name,
        "connection_id" : connection_info["id"],
        "query_text": connection_info["connection_name"],
        "query_status": False,
        "query_type": False,
        "created_user" : requestQueryData["Page1"]["created_user"],
        "created_by" : connection_info["created_by"],
        "last_updated_by" : connection_info["last_updated_by"]
    }
    
    if "id" in requestQueryData["Page1"]:
        dataDefinitionTable = query_definition.objects.get(id=requestQueryData["Page1"]["id"])
        queryDefnitionSerilazier = qb_defnition_serializer(instance=dataDefinitionTable,data=postConnData)
        
        if queryDefnitionSerilazier.is_valid():
            queryDefnitionSerilazier.save()
            fun_ins_upd_builder_table(requestQueryData,queryDefnitionSerilazier.data["id"],connection_info["created_by"],connection_info["last_updated_by"])
            
        
    else:
        queryDefnitionSerilazier = qb_defnition_serializer(data=postConnData)
        if queryDefnitionSerilazier.is_valid():
            queryDefnitionSerilazier.save()
            fun_ins_upd_builder_table(requestQueryData,queryDefnitionSerilazier.data["id"],connection_info["created_by"],connection_info["last_updated_by"])
            return Response(requestQueryData, status=status.HTTP_200_OK)
            # return Response(requestQueryData,status = status.HTTP_201_CREATED)
    
    return Response(queryDefnitionSerilazier.errors,status = status.HTTP_400_BAD_REQUEST)
    
    

def find_column_alias(aliasList, table_name, colName):        
        if len(aliasList) >= 1:
            for alias in aliasList:
                if alias['selectedColumnName'] == colName and alias['selectedTableName'] == table_name:
                    return alias


def find_table(tableList, table_name):
    for tabledata in tableList:
        if tabledata['tb_name'] == table_name:
            return tabledata['id']
            
            
def findColumnId(requestAggregateData,column_id):
    for  columnName in column_id:
        if columnName["column_name"] == requestAggregateData:
            return columnName["id"]


