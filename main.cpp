#include "crow.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>
#include <fmt/core.h>
#include "faucet-helpers.h"

using ReturnType = std::tuple<crow::json::wvalue, bool, int>;
using RpcReturnType = std::tuple<crow::json::wvalue, int>;

namespace nl = nlohmann;


struct CORS {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context&) {
        if (req.method == "OPTIONS"_method) {
            res.code = 204;
            setCorsHeaders(res);
            res.end();
        }
    }

    void after_handle(crow::request&, crow::response& res, context&, crow::detail::context<CORS>&) {
        setCorsHeaders(res);
    }

    void setCorsHeaders(crow::response& res) {
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
};

  
int main() {
    
    try {
        crow::App<CORS> app;

        CROW_ROUTE(app, "/transfer").methods("POST"_method)([](const crow::request& req){
            crow::json::wvalue res;

            try {
                faucetHelper helper;
                crow::json::rvalue body = crow::json::load(req.body);
                if (!body)
                    return crow::response(400, "Invalid JSON");

                std::string tnAddr = body["userInput"].s();

                // Get IP
                std::string clientIP = helper.getClientIP(req);
                std::cout << "User IP : " << clientIP << std::endl;

                
                // validate client testnet address
                bool addressValid = helper.validateTestnetAddress(tnAddr);
                std::cout << "Address valid : " << addressValid << std::endl;

                if (addressValid) {
                    // Check IP restrict
                    ReturnType result = helper.isIpRestrict(clientIP);

                    auto [response, is_restricted, statuscode] = result;
                    std::cout << "IP Statuscode : " << statuscode << std::endl;
                    std::cout << "IP Restricted : " << is_restricted << std::endl;


                    if (!is_restricted) {
                        // Transfer faucet
                        RpcReturnType rpcResult = helper.transferRequest(tnAddr, clientIP);
                        auto [rpcResponse, rpcStatuscode] = rpcResult;

                        return crow::response(rpcStatuscode, rpcResponse);
                    } else {
                        return crow::response(statuscode, response);
                    }
                    
                } else {
                    res["address"] = "The address provided is invalid. Kindly ensure that you enter a valid testnet address and try again.";
                    return crow::response(400, res);
                }

            } catch (const std::exception& e) {
                faucetHelper::logger << "[EXCEPTION] Exception in /transfer handler: " << e.what() << std::endl;
                res["error"] = "Something went wrong.";
                return crow::response(500, res);
            
            } catch (...) {
                faucetHelper::logger << "[EXCEPTION] Unknown exception in /transfer handler." << std::endl;
                res["error"] = "Something went wrong.";
                return crow::response(500, res);
            }
        });

        app.port(5000).multithreaded().run();
    }
    catch (const std::exception& e) {
        faucetHelper::logger << "[EXCEPTION] Exception in main: " << e.what() << std::endl;
    }


    return 0;
}
