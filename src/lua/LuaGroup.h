#ifndef LUAGROUP_H
#define LUAGROUP_H

#include "Lua.h"
#include "LuaEntry.h"
#include "core/Group.h"

#include <QDebug>

class LuaGroup
{
public:
    static void Initialize(lua_State *L)
    {
        static luaL_Reg methods[] = {
            { "uuid", uuid },
            { "name", name },
            { "notes", notes },
            { "entries", entries },
            { 0, 0 }
        };

        luaL_newlib(L, methods);
        luaL_newmetatable(L, "Group");
        lua_pushliteral(L, "__index");
        lua_pushvalue(L, -3);
        lua_rawset(L, -3);
        lua_pop(L, 2);
    }

    static void push(lua_State *L, Group *group)
    {
        *static_cast<void **>(lua_newuserdata(L, sizeof(void*))) = group;
        luaL_getmetatable(L, "Group");
        lua_setmetatable(L, -2);
    }
private:
    LuaGroup() {}

    static Group *check(lua_State *L)
    {
        luaL_checkudata(L, 1, "Group");
        return *static_cast<Group **>(lua_touserdata(L, 1));
    }

    static int uuid(lua_State *L)
    {
        lua_pushstring(L, check(L)->uuid().toHex().toLatin1().data());
        return 1;
    }

    static int name(lua_State *L)
    {
        lua_pushstring(L, check(L)->name().toLatin1().data());
        return 1;
    }

    static int notes(lua_State *L)
    {
        lua_pushstring(L, check(L)->name().toLatin1().data());
        return 1;
    }

    static int entries(lua_State *L)
    {
        Group *group = check(L);

        lua_newtable(L);

        int i = 1;
        for (Entry *entry : group->entries()) {
            lua_pushnumber(L, i++);
            LuaEntry::push(L, entry);
            lua_rawset(L, -3);
        }

        return 1;
    }
};

#endif // LUAGROUP_H
