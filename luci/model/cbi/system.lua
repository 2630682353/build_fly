


m1 = Map("system", translate(""))
                                                                                 
s = m1:section(TypedSection, "_dummy", "系统用户密码")                                        
s.addremove = false                                                              
s.anonymous = true                                                               
                                                                                 
pw1 = s:option(Value, "pw1", translate("Password"))                              
pw1.password = true                                                              
                                                                                 
pw2 = s:option(Value, "pw2", translate("Confirmation"))                          
pw2.password = true                                                              
                                                                                 
function s.cfgsections()                                                         
        return { "_pass" }                                                       
end                                                    
                                                       
function m1.on_commit(map)                              
        local v1 = pw1:formvalue("_pass")              
        local v2 = pw2:formvalue("_pass")              
                                                       
        if v1 and v2 and #v1 > 0 and #v2 > 0 then      
                if v1 == v2 then                       
                        if luci.sys.user.setpasswd(luci.dispatcher.context.authuser, v1) == 0 then
                                m1.message = translate("Password successfully changed!")           
                        else                                                                      
                                m1.message = translate("Unknown Error, password not changed!")     
                        end                                                                       
                else                                                                              
                        m1.message = translate("Given password confirmation did not match, password not changed!")
                end                                                                                              
        end                                                                                                      
end



return m1
