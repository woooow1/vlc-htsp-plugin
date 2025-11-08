/*****************************************************************************
 * Copyright (C) 2012
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#define __STDC_CONSTANT_MACROS 1

#include <functional>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include <list>
#include <vector>
#include <algorithm>

#include "discovery.h"
#include "helper.h"
#include "htsmessage.h"
#include "sha1.h"

#include <vlc_common.h>
#include <vlc_plugin.h>
#include <vlc_network.h>
#include <vlc_services_discovery.h>

struct tmp_channel
{
    std::string name;
    uint32_t cid;
    uint32_t cnum;
    std::string url;
    std::string cicon;
    std::list<std::string> tags;
};

struct services_discovery_sys_t : public sys_common_t
{
    services_discovery_sys_t()
#if CHECK_VLC_VERSION(3, 0)
        :thread({0})
#else
        :thread(0)
#endif
        ,disconnect(false)
    {}

    vlc_thread_t thread;
    std::unordered_map<uint32_t, tmp_channel> channelMap;
    bool disconnect;
};

/* ------------------------------------------------------------------------- */

static void ExportM3U(const std::unordered_map<uint32_t, tmp_channel>& channels,
                      const std::string &filepath,
                      vlc_object_t *obj)
{
    std::ofstream m3uFile(filepath);
    if (!m3uFile.is_open())
        return;

    m3uFile << "#EXTM3U\n";

    std::vector<tmp_channel> sortedChannels;
    for (auto &pair : channels)
        sortedChannels.push_back(pair.second);

    std::sort(sortedChannels.begin(), sortedChannels.end(),
              [](const tmp_channel &a, const tmp_channel &b) { return a.cnum < b.cnum; });

    for (const auto &ch : sortedChannels)
    {
        m3uFile << "#EXTINF:-1";
        if (!ch.name.empty())
        {
            m3uFile << " tvg-id=\"" << ch.cid << "\"";
            m3uFile << " tvg-name=\"" << ch.name << "\"";
            if (!ch.cicon.empty())
                m3uFile << " tvg-logo=\"" << ch.cicon << "\"";
        }
        m3uFile << "," << ch.cnum << " - " << ch.name << "\n";
        m3uFile << ch.url << "\n";
    }

    m3uFile.close();
    msg_Info(obj, "HTSP DEBUG: exported M3U with %zu channels", channels.size());
}

/* ------------------------------------------------------------------------- */

static void AddChannel(const tmp_channel &ch, services_discovery_sys_t *sys)
{
    sys->channelMap[ch.cid] = ch;
}

/* ------------------------------------------------------------------------- */

static void AddChannelsToVLC(services_discovery_t *sd, services_discovery_sys_t *sys)
{
    msg_Info(sd, "HTSP DEBUG: adding channels to VLC playlist...");

    std::vector<tmp_channel> sortedChannels;
    for (auto &pair : sys->channelMap)
        sortedChannels.push_back(pair.second);

    std::sort(sortedChannels.begin(), sortedChannels.end(),
        [](const tmp_channel &a, const tmp_channel &b) { return a.cnum < b.cnum; });

    for (auto &ch : sortedChannels)
    {
        std::ostringstream displayName;
        displayName << ch.cnum << " - " << ch.name;

        input_item_t *item = input_item_New(ch.url.c_str(), displayName.str().c_str());
        if (!item)
        {
            msg_Err(sd, "HTSP DEBUG: failed to create input_item for channel %s", ch.name.c_str());
            continue;
        }

        if (!ch.cicon.empty())
            input_item_SetArtURL(item, ch.cicon.c_str());

        // Добавяне към VLC SD
        services_discovery_AddItem(sd, item);
        input_item_Release(item);

        msg_Info(sd, "HTSP DEBUG: added channel '%s' (%u) to VLC", ch.name.c_str(), ch.cid);
    }
}

/* ------------------------------------------------------------------------- */

static bool ConnectSD(services_discovery_t *sd)
{
    services_discovery_sys_t *sys = sd->p_sys;

    char *host = var_GetString(sd, CFG_PREFIX"host");
    int port = var_GetInteger(sd, CFG_PREFIX"port");
    sys->disconnect = var_GetBool(sd, CFG_PREFIX"disconnect");

    if (port == 0)
        port = 9982;

    msg_Info(sd, "HTSP DEBUG: connecting to %s:%d", host && host[0] ? host : "localhost", port);

    if (host == nullptr || host[0] == 0)
        sys->netfd = net_ConnectTCP(sd, "localhost", port);
    else
        sys->netfd = net_ConnectTCP(sd, host, port);

    if (host) free(host);
    if (sys->netfd < 0)
    {
        msg_Err(sd, "HTSP DEBUG: net_ConnectTCP failed");
        return false;
    }

    // Hello
    HtsMap map;
    map.setData("method", "hello");
    map.setData("clientname", "VLC media player");
    map.setData("htspversion", HTSP_PROTO_VERSION);

    HtsMessage m = ReadResult(sd, sys, map.makeMsg());
    if (!m.isValid())
    {
        msg_Err(sd, "HTSP DEBUG: failed to receive hello response");
        return false;
    }

    uint32_t chall_len;
    void *chall;
    m.getRoot()->getBin("challenge", &chall_len, &chall);

    char *user = var_GetString(sd, CFG_PREFIX"user");
    char *pass = var_GetString(sd, CFG_PREFIX"pass");

    map = HtsMap();
    map.setData("method", "authenticate");
    map.setData("username", user ? user : "");

    if (pass && pass[0] && chall)
    {
        HTSSHA1 *shactx = (HTSSHA1*)malloc(hts_sha1_size);
        uint8_t d[20];
        hts_sha1_init(shactx);
        hts_sha1_update(shactx, (const uint8_t *)pass, strlen(pass));
        hts_sha1_update(shactx, (const uint8_t *)chall, chall_len);
        hts_sha1_final(shactx, d);

        std::shared_ptr<HtsBin> bin = std::make_shared<HtsBin>();
        bin->setBin(20, d);
        map.setData("digest", bin);

        free(shactx);
    }

    if (user) free(user);
    if (pass) free(pass);
    if (chall) free(chall);

    bool ok = ReadSuccess(sd, sys, map.makeMsg(), "authenticate");
    if (ok)
        msg_Info(sd, "HTSP DEBUG: authentication successful");
    else
        msg_Err(sd, "HTSP DEBUG: authentication failed");

    return ok;
}

/* ------------------------------------------------------------------------- */

static bool GetChannels(services_discovery_t *sd)
{
    services_discovery_sys_t *sys = sd->p_sys;
    msg_Info(sd, "HTSP DEBUG: requesting channel list...");

    HtsMap map;
    map.setData("method", "enableAsyncMetadata");
    if (!ReadSuccess(sd, sys, map.makeMsg(), "enable async metadata"))
        return false;

    HtsMessage m;
    while ((m = ReadMessage(sd, sys)).isValid())
    {
        std::string method = m.getRoot()->getStr("method");
        if (method.empty() || method == "initialSyncCompleted")
            break;

        if (method == "channelAdd")
        {
            uint32_t cid = m.getRoot()->getU32("channelId");
            std::string cname = m.getRoot()->getStr("channelName");
            uint32_t cnum = m.getRoot()->getU32("channelNumber");
            std::string cicon = m.getRoot()->getStr("channelIcon");

            std::ostringstream oss;
            oss << "htsp://";

            char *user = var_GetString(sd, CFG_PREFIX"user");
            char *pass = var_GetString(sd, CFG_PREFIX"pass");
            if (user && user[0] && pass && pass[0])
                oss << user << ":" << pass << "@";
            else if (user && user[0])
                oss << user << "@";

            char *_host = var_GetString(sd, CFG_PREFIX"host");
            const char *host = (_host && _host[0]) ? _host : "localhost";
            int port = var_GetInteger(sd, CFG_PREFIX"port");
            if (port == 0) port = 9982;
            oss << host << ":" << port << "/" << cid;

            tmp_channel ch = { cname, cid, cnum, oss.str(), cicon, {} };
            AddChannel(ch, sys);

            msg_Info(sd, "HTSP DEBUG: channel #%u '%s' added", cid, cname.c_str());

            if (user) free(user);
            if (pass) free(pass);
            if (_host) free(_host);
        }
    }

    ExportM3U(sys->channelMap, "/tmp/tvh_channels.m3u", (vlc_object_t*)sd);
    AddChannelsToVLC(sd, sys);

    msg_Info(sd, "HTSP DEBUG: total channels loaded: %zu", sys->channelMap.size());
    return true;
}

/* ------------------------------------------------------------------------- */

static void *RunSD(void *obj)
{
    services_discovery_t *sd = (services_discovery_t *)obj;
    services_discovery_sys_t *sys = sd->p_sys;

    msg_Info(sd, "HTSP DEBUG: discovery thread started");

    if (!ConnectSD(sd))
        return nullptr;

    if (!GetChannels(sd))
        msg_Err(sd, "HTSP DEBUG: failed to get channels");

    while (!sys->disconnect)
    {
        HtsMessage msg = ReadMessage(sd, sys);
        if (!msg.isValid())
            break;
    }

    net_Close(sys->netfd);
    msg_Info(sd, "HTSP DEBUG: discovery thread finished");
    return nullptr;
}

/* ------------------------------------------------------------------------- */

int OpenSD(vlc_object_t *obj)
{
    services_discovery_t *sd = (services_discovery_t *)obj;
    services_discovery_sys_t *sys = new services_discovery_sys_t;
    if (!sys)
        return VLC_ENOMEM;

    sd->p_sys = sys;

    config_ChainParse(sd, CFG_PREFIX, cfg_options, sd->p_cfg);

    if (vlc_clone(&sys->thread, RunSD, sd, VLC_THREAD_PRIORITY_LOW))
    {
        delete sys;
        return VLC_EGENERIC;
    }

    msg_Info(sd, "HTSP DEBUG: OpenSD successful");
    return VLC_SUCCESS;
}

/* ------------------------------------------------------------------------- */

void CloseSD(vlc_object_t *obj)
{
    services_discovery_t *sd = (services_discovery_t *)obj;
    services_discovery_sys_t *sys = sd->p_sys;
    if (!sys)
        return;

#if CHECK_VLC_VERSION(3, 0)
    if (sys->thread.handle)
#else
    if (sys->thread)
#endif
    {
        vlc_cancel(sys->thread);
        vlc_join(sys->thread, nullptr);
#if CHECK_VLC_VERSION(3, 0)
        sys->thread.handle = 0;
#else
        sys->thread = 0;
#endif
    }

    delete sys;
    sd->p_sys = nullptr;
    msg_Info(sd, "HTSP DEBUG: CloseSD finished");
}
