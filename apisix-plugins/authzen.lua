--Copyright 2026 TwoGenIdentity. All Rights Reserved.
--

local core        =   require("apisix.core")
local http        =   require("resty.http")
local jwt         =   require("resty.jwt")

local log = core.log

local plugin_name = "authzen"
local plugin_cache_name = "authzen_store"

local schema = {
    type = "object",
    properties = {
        pdp = {
            type = "object",
            properties = {
                host = {
                    type = "string",
                    description = "PDP base URL (e.g., https://pdp.example.com)"
                },
                platform = {
                    type = "string",
                    enum = {"default", "openfga", "cerbos"},
                    default = "default",
                    description = "PDP platform type (e.g., openfga, cerbos)"
                },
                model = {
                    type = "string",
                    default = "discover",
                    description = "For OpenFGA: 'discover' to auto-discover store_id, or specify store_id directly"
                },
                api_key = {
                    type = "string",
                    description = "Optional API key for PDP authentication"
                }
            },
            required = {"host"}
        },
        http = {
            type = "object",
            properties = {
                timeout = {
                    type = "integer",
                    minimum = 1,
                    maximum = 60000,
                    default = 3000,
                    description = "Timeout in milliseconds"
                },
                ssl_verify = {
                    type = "boolean",
                    default = false,
                    description = "SSL certificate verification"
                },
                keepalive = {
                    type = "boolean",
                    default = true
                },
                keepalive_timeout = {
                    type = "integer",
                    minimum = 1000,
                    default = 60000
                },
                keepalive_pool = {
                    type = "integer",
                    minimum = 1,
                    default = 5
                }
            },
            default = {
                timeout = 3000,
                ssl_verify = false,
                keepalive = true,
                keepalive_timeout = 60000,
                keepalive_pool = 5
            }
        },
        subject = {
            type = "object",
            properties = {
                type = {
                    type = "string",
                    default = "identity",
                    description = "Subject type for AuthZEN request"
                },
                id = {
                    type = "string",
                    default = "claim::sub",
                    description = "Subject ID source: 'claim::<claim_name>' for JWT claim"
                },
                properties = {
                    type = "array",
                    items = {
                        type = "object",
                        properties = {
                            key = {
                                type = "string",
                                description = "Property name in AuthZEN request"
                            },
                            claim = {
                                type = "string",
                                description = "JWT claim path (e.g., 'realm_access.roles')"
                            }
                        },
                        required = {"key", "claim"}
                    },
                    description = "Array of JWT claim mappings to subject properties"
                }
            },
            default = {
                type = "identity",
                id = "claim::sub"
            }
        },
        resource = {
            type = "object",
            properties = {
                type = {
                    type = "string",
                    default = "route",
                    description = "Resource type for AuthZEN request"
                },
                id = {
                    type = "string",
                    default = "uri",
                    description = "Resource ID source: 'uri' for request URI or static value"
                }
            },
            default = {
                type = "route",
                id = "uri"
            }
        },
        action = {
            type = "object",
            properties = {
                name = {
                    type = "string",
                    default = "method",
                    description = "Action name source: 'method' for HTTP method or static value"
                }
            },
            default = {
                name = "method"
            }
        }
    },
    required = {"pdp"}
}


local _M = {
    version = 0.1,
    priority = 2599,
    name = plugin_name,
    schema = schema
}


function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end


local function cache_set(key, value, exp)
    local dict = ngx.shared[plugin_cache_name]
    if dict then
        local success, err = dict:set(key, value, exp)
        if err then
            log.error("[authzen] cache_set error: ", err)
        end
    end
end


local function cache_get(key)
    local dict = ngx.shared[plugin_cache_name]
    if dict then
        return dict:get(key)
    end
    return nil
end


local function discover_openfga_store_id(conf)
    local cached = cache_get(conf.pdp.host)
    if cached then
        log.debug("[authzen] using cached store_id: ", cached)
        return cached, nil
    end

    log.debug("[authzen] discovering OpenFGA store_id from: ", conf.pdp.host)

    local http_conf = conf.http or {}
    local params = {
        method = "GET",
        headers = {
            ["Content-Type"] = "application/json"
        },
        keepalive = http_conf.keepalive,
        ssl_verify = http_conf.ssl_verify
    }

    if http_conf.keepalive then
        params.keepalive_timeout = http_conf.keepalive_timeout
        params.keepalive_pool = http_conf.keepalive_pool
    end

    if conf.pdp.api_key then
        params.headers["Authorization"] = conf.pdp.api_key
    end

    local endpoint = conf.pdp.host .. "/stores"

    local httpc = http.new()
    httpc:set_timeout(http_conf.timeout or 3000)
    local res, err = httpc:request_uri(endpoint, params)

    if not res then
        log.error("[authzen] failed to fetch stores: ", err)
        return nil, "failed to fetch stores: " .. (err or "unknown error")
    end

    if res.status ~= 200 then
        log.error("[authzen] stores endpoint returned status: ", res.status)
        return nil, "stores endpoint returned status: " .. res.status
    end

    local json_stores, err = core.json.decode(res.body)
    if not json_stores then
        log.error("[authzen] failed to decode stores response: ", err)
        return nil, "failed to decode stores response"
    end

    if not json_stores.stores or #json_stores.stores == 0 then
        log.error("[authzen] no stores found")
        return nil, "no stores found in OpenFGA"
    end

    local store_id = json_stores.stores[1].id
    log.info("[authzen] discovered OpenFGA store_id: ", store_id)

    cache_set(conf.pdp.host, store_id, 3600)

    return store_id, nil
end


local function build_pdp_endpoint(conf)
    local host = conf.pdp.host
    local platform = conf.pdp.platform or "default"
    local model = conf.pdp.model or "discover"

    if platform == "openfga" then
        local store_id
        if model == "discover" then
            local err
            store_id, err = discover_openfga_store_id(conf)
            if not store_id then
                return nil, err
            end
        else
            store_id = model
            log.info("[authzen] using configured store_id: ", store_id)
        end
        return host .. "/stores/" .. store_id .. "/access/v1/evaluation", nil
    end

    return host .. "/access/v1/evaluation", nil
end


local function get_jwt_claim_value(authorization_header, claim_name)
    if not authorization_header then
        return nil, "authorization header not available"
    end

    local jwt_token = string.sub(authorization_header, 8)
    local jwt_obj = jwt:load_jwt(jwt_token)

    if not jwt_obj or not jwt_obj.payload then
        return nil, "failed to decode JWT token"
    end

    local value = jwt_obj.payload[claim_name]
    if not value then
        return nil, "claim '" .. claim_name .. "' not found in JWT"
    end

    return value, nil
end


local function split_path(path, delimiter)
    local result = {}
    for part in string.gmatch(path, "[^" .. delimiter .. "]+") do
        table.insert(result, part)
    end
    return result
end


local function get_nested_claim(payload, claim_path)
    local parts = split_path(claim_path, ".")
    local value = payload
    for _, part in ipairs(parts) do
        if type(value) ~= "table" then
            return nil
        end
        value = value[part]
        if value == nil then
            return nil
        end
    end
    return value
end


local function get_jwt_payload(authorization_header)
    if not authorization_header then
        return nil, "authorization header not available"
    end

    local jwt_token = string.sub(authorization_header, 8)
    local jwt_obj = jwt:load_jwt(jwt_token)

    if not jwt_obj or not jwt_obj.payload then
        return nil, "failed to decode JWT token"
    end

    return jwt_obj.payload, nil
end


local function build_subject_properties(conf_properties, jwt_payload)
    if not conf_properties or #conf_properties == 0 then
        return nil
    end

    local properties = {}
    for _, prop in ipairs(conf_properties) do
        log.info("[authzen] searching jwt claim: ", prop.claim)
        local value = get_nested_claim(jwt_payload, prop.claim)
        if value ~= nil then
            properties[prop.key] = value
        end
    end

    if next(properties) == nil then
        return nil
    end

    return properties
end


local function get_subject_id(conf, ctx)
    local subject_id_source = conf.subject and conf.subject.id or "claim::sub"
    
    if subject_id_source:sub(1, 7) == "claim::" then
        local claim_name = subject_id_source:sub(8)
        local authorization_header = core.request.header(ctx, "Authorization")
        return get_jwt_claim_value(authorization_header, claim_name)
    end

    return subject_id_source, nil
end


local function get_resource_id(conf, ctx)
    local resource_id_source = conf.resource and conf.resource.id or "uri"

    if resource_id_source == "uri" then
        return ctx.var.uri, nil
    end

    return resource_id_source, nil
end


local function get_action_name(conf, ctx)
    local action_name_source = conf.action and conf.action.name or "method"

    if action_name_source == "method" then
        return ctx.var.request_method, nil
    end

    return action_name_source, nil
end


local function build_authzen_request(conf, ctx)
    local subject_id, err = get_subject_id(conf, ctx)
    if not subject_id then
        return nil, "failed to get subject ID: " .. (err or "unknown error")
    end

    local resource_id, err = get_resource_id(conf, ctx)
    if not resource_id then
        return nil, "failed to get resource ID: " .. (err or "unknown error")
    end

    local action_name, err = get_action_name(conf, ctx)
    if not action_name then
        return nil, "failed to get action name: " .. (err or "unknown error")
    end

    local subject_properties = nil
    if conf.subject and conf.subject.properties then
        local authorization_header = core.request.header(ctx, "Authorization")
        local jwt_payload, jwt_err = get_jwt_payload(authorization_header)
        if jwt_payload then
            subject_properties = build_subject_properties(conf.subject.properties, jwt_payload)
        else
            log.warn("[authzen] could not extract JWT payload for properties: ", jwt_err or "unknown error")
        end
    end

    local authzen_request = {
        subject = {
            type = conf.subject and conf.subject.type or "identity",
            id = subject_id,
            properties = subject_properties
        },
        resource = {
            type = conf.resource and conf.resource.type or "route",
            id = resource_id
        },
        action = {
            name = action_name
        }
    }

    return authzen_request, nil
end


function _M.access(conf, ctx)
    log.info("[authzen] starting authorization check")

    local authzen_request, err = build_authzen_request(conf, ctx)
    if not authzen_request then
        log.error("[authzen] failed to build request: ", err)
        return 401, {message = err}
    end

    local body = core.json.encode(authzen_request)
    log.info("[authzen] request: ", body)

    local headers = {
        ["Content-Type"] = "application/json"
    }

    if conf.pdp.api_key then
        headers["Authorization"] = conf.pdp.api_key
    end

    local http_conf = conf.http or {}
    local params = {
        method = "POST",
        body = body,
        headers = headers,
        keepalive = http_conf.keepalive,
        ssl_verify = http_conf.ssl_verify
    }

    if http_conf.keepalive then
        params.keepalive_timeout = http_conf.keepalive_timeout
        params.keepalive_pool = http_conf.keepalive_pool
    end

    local endpoint, err = build_pdp_endpoint(conf)
    if not endpoint then
        log.error("[authzen] failed to build endpoint: ", err)
        return 503, {message = "Failed to connect to authorization service"}
    end
    log.info("[authzen] calling endpoint: ", endpoint)

    local httpc = http.new()
    httpc:set_timeout(http_conf.timeout or 3000)

    local res, err = httpc:request_uri(endpoint, params)

    if not res then
        log.error("[authzen] failed to call PDP, err: ", err)
        return 503, {message = "Authorization service unavailable"}
    end

    if res.status ~= 200 then
        log.error("[authzen] PDP returned status: ", res.status, " body: ", res.body)
        return 503, {message = "Authorization service error"}
    end

    local data, err = core.json.decode(res.body)
    if not data then
        log.error("[authzen] invalid response body: ", res.body, " err: ", err)
        return 503, {message = "Invalid authorization response"}
    end

    log.debug("[authzen] response: ", core.json.encode(data))

    if not data.decision then
        log.info("[authzen] access denied for subject: ", authzen_request.subject.id)
        return 403, {message = "Access denied"}
    end

    log.info("[authzen] access granted for subject: ", authzen_request.subject.id)
end


return _M
