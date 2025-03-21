#pragma once

#define LONG_STRING_CONST(...) #__VA_ARGS__

const char plugin_schema_string[] = LONG_STRING_CONST(

{
   "$schema":"http://json-schema.org/draft-04/schema#",
   "required":[],
   "properties":{
      "label_max_len":{
         "type":"integer",
         "title":"Max label length",
         "description":"Labels exceeding this limit won't be reported."
      },
      "with_size":{
         "type":"boolean",
         "title":"Inspect containers with size",
         "description":"Inspect containers size where supported."
      },
      "engines":{
         "$ref":"#/definitions/Engines",
         "title":"The plugin per-engine configuration",
         "description":"Allows to disable/enable each engine and customize sockets where available."
      }
   },
   "definitions":{
      "Engines":{
         "type":"object",
         "additionalProperties":false,
         "properties":{
            "docker":{
               "$ref":"#/definitions/SocketsContainer"
            },
            "podman":{
               "$ref":"#/definitions/SocketsContainer"
            },
            "containerd":{
               "$ref":"#/definitions/SocketsContainer"
            },
            "cri":{
               "$ref":"#/definitions/SocketsContainer"
            },
            "lxc":{
               "$ref":"#/definitions/SimpleContainer"
            },
            "libvirt_lxc":{
               "$ref":"#/definitions/SimpleContainer"
            },
            "bpm":{
               "$ref":"#/definitions/SimpleContainer"
            },
            "static":{
               "$ref":"#/definitions/StaticContainer"
            }
         },
         "required":[
            "bpm",
            "containerd",
            "cri",
            "docker",
            "libvirt_lxc",
            "lxc",
            "podman"
         ],
         "title":"Engines"
      },
      "nonEmptyString":{
         "type":"string",
         "minLength":1
      },
      "SimpleContainer":{
         "type":"object",
         "additionalProperties":false,
         "properties":{
            "enabled":{
               "type":"boolean"
            }
         },
         "required":[
            "enabled"
         ],
         "title":"SimpleContainer"
      },
      "SocketsContainer":{
         "type":"object",
         "additionalProperties":false,
         "properties":{
            "enabled":{
               "type":"boolean"
            },
            "sockets":{
               "type":"array",
               "items":{
                  "type":"string"
               }
            }
         },
         "required":[
            "enabled",
            "sockets"
         ],
         "title":"SocketsContainer"
      },
      "StaticContainer":{
         "type":"object",
         "additionalProperties":false,
         "properties":{
            "enabled":{
               "type":"boolean"
            },
            "container_id":{
               "$ref":"#/definitions/nonEmptyString"
            },
            "container_name":{
               "$ref":"#/definitions/nonEmptyString"
            },
            "container_image":{
               "$ref":"#/definitions/nonEmptyString"
            }
         },
         "required":[
            "enabled",
            "container_id",
            "container_name",
            "container_image"
         ],
         "title":"StaticContainer"
      }
   },
   "additionalProperties":false,
   "type":"object"
}

); // LONG_STRING_CONST macro

