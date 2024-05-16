package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"time"

	consul_api "github.com/hashicorp/consul/api"
	"github.com/samuel/go-zookeeper/zk"
	client "go.etcd.io/etcd/client/v2"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/pkg/transport"
)

var lastFoundClusterMembers = make(map[string][]PatroniClusterMember) // needed for cases where DCS is temporarily down
// don't want to immediately remove monitoring of DBs

func ParseHostAndPortFromJdbcConnStr(connStr string) (string, string, error) {
	r := regexp.MustCompile(`postgres://(.*)+:([0-9]+)/`)
	matches := r.FindStringSubmatch(connStr)
	if len(matches) != 3 {
		log.Errorf("Unexpected regex result groups:", matches)
		return "", "", fmt.Errorf("unexpected regex result groups: %v", matches)
	}
	return matches[1], matches[2], nil
}

func ConsulGetClusterMembers(database MonitoredDatabase) ([]PatroniClusterMember, error) {
	var ret []PatroniClusterMember

	if len(database.HostConfig.DcsEndpoints) == 0 {
		return ret, errors.New("Missing Consul connect info, make sure host config has a 'dcs_endpoints' key")
	}

	config := consul_api.Config{}
	config.Address = database.HostConfig.DcsEndpoints[0]
	if config.Address[0] == '/' { // Consul doesn't have leading slashes
		config.Address = config.Address[1 : len(config.Address)-1]
	}
	client, err := consul_api.NewClient(&config)
	if err != nil {
		log.Error("Could not connect to Consul", err)
		return ret, err
	}

	kv := client.KV()

	membersPath := path.Join(database.HostConfig.Namespace, database.HostConfig.Scope, "members")
	members, _, err := kv.List(membersPath, nil)
	if err != nil {
		log.Error("Could not read Patroni members from Consul:", err)
		return ret, err
	}
	for _, member := range members {
		name := path.Base(member.Key)
		log.Debugf("Found a cluster member from Consul: %+v", name)
		nodeData, err := jsonTextToStringMap(string(member.Value))
		if err != nil {
			log.Errorf("Could not parse Consul node data for node \"%s\": %s", name, err)
			continue
		}
		role := nodeData["role"]
		connUrl := nodeData["conn_url"]

		ret = append(ret, PatroniClusterMember{Scope: database.HostConfig.Scope, ConnUrl: connUrl, Role: role, Name: name})
	}

	return ret, nil
}

func EtcdGetClusterMembers(database MonitoredDatabase) ([]PatroniClusterMember, error) {
	var ret = make([]PatroniClusterMember, 0)
	var cfg client.Config
	var cfgv3 clientv3.Config
	var CAFile = database.HostConfig.CAFile
	var CertFile = database.HostConfig.CertFile
	var KeyFile = database.HostConfig.KeyFile

	if database.HostConfig.DcsType == DCS_TYPE_ETCD {
		log.Warning("Configured ETCD uses API version 2 which will be deprecated in etcd v3.6, consider upgrading to etcd api v3 with dcs_type: etcd3")
	}
	if len(database.HostConfig.DcsEndpoints) == 0 {
		return ret, errors.New("Missing ETCD connect info, make sure host config has a 'dcs_endpoints' key")
	}

	if database.HostConfig.CAFile != "" || database.HostConfig.KeyFile != "" || database.HostConfig.CertFile != "" {
		if database.HostConfig.CAFile != "" {
			if _, err := os.Stat(database.HostConfig.CAFile); os.IsNotExist(err) {
				log.Warningf("Configured CAFile for Patroni cluster '%s' not found, ignoring the file: %s", database.DBUniqueName, database.HostConfig.CAFile)
				CAFile = ""
			}
		}
		if database.HostConfig.CertFile != "" {
			if _, err := os.Stat(database.HostConfig.CertFile); os.IsNotExist(err) {
				log.Warningf("Configured CertFile for Patroni cluster '%s' not found, ignoring the file: %s", database.DBUniqueName, database.HostConfig.CertFile)
				CertFile = ""
			}
		}
		if database.HostConfig.KeyFile != "" {
			if _, err := os.Stat(database.HostConfig.KeyFile); os.IsNotExist(err) {
				log.Warningf("Configured KeyFile for Patroni cluster '%s' not found, ignoring the file: %s", database.DBUniqueName, database.HostConfig.KeyFile)
				KeyFile = ""
			}
		}
		if database.HostConfig.DcsType == DCS_TYPE_ETCD {
			tlsv2 := transport.TLSInfo{
				TrustedCAFile: CAFile,
				CertFile:      CertFile,
				KeyFile:       KeyFile,
			}
			//log.Debugf("Setting ETCD TLS config for %s: %+v", database.DBUniqueName, tlsv2)
			dialTimeout := 10 * time.Second
			etcdTransport, _ := transport.NewTransport(tlsv2, dialTimeout)
			cfg = client.Config{
				Endpoints:               database.HostConfig.DcsEndpoints,
				Transport:               etcdTransport,
				HeaderTimeoutPerRequest: time.Second,
				Username:                database.HostConfig.Username,
				Password:                database.HostConfig.Password,
			}
		} else if database.HostConfig.DcsType == DCS_TYPE_ETCD_V3 {
			// V3 config
			cert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
			if err != nil {
				log.Warningf("EtcdV3: loading certificates (key %s, cert %s) failed:", KeyFile, CertFile, err)
			}

			// Configure the server to trust TLS client certs issued by a CA.
			certPool, err := x509.SystemCertPool()
			if err != nil {
				log.Warning("Etcdv3: cannot read System Cert Pool:", err)
			}
			caCertPEM, err := os.ReadFile(CAFile)
			if err != nil {
				log.Warningf("EtcdV3: cannot read CACert %s : %s", CAFile, err)
			} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
				panic("invalid cert in CA PEM")
			}

			tlsv3 := &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert, // enforce mTLS client authentication.
				ClientCAs:    certPool,
				Certificates: []tls.Certificate{cert},
			}
			cfgv3 = clientv3.Config{
				Endpoints: database.HostConfig.DcsEndpoints,
				TLS:       tlsv3,
				Username:  database.HostConfig.Username,
				Password:  database.HostConfig.Password,
			}
		}
	} else {
		if database.HostConfig.DcsType == DCS_TYPE_ETCD {
			cfg = client.Config{
				Endpoints:               database.HostConfig.DcsEndpoints,
				Transport:               client.DefaultTransport,
				HeaderTimeoutPerRequest: time.Second,
				Username:                database.HostConfig.Username,
				Password:                database.HostConfig.Password,
			}
		} else if database.HostConfig.DcsType == DCS_TYPE_ETCD_V3 {
			// V3 config
			cfgv3 = clientv3.Config{
				Endpoints: database.HostConfig.DcsEndpoints,
				Username:  database.HostConfig.Username,
				Password:  database.HostConfig.Password,
			}
		}
	}
	if database.HostConfig.DcsType == DCS_TYPE_ETCD {
		c, err := client.New(cfg)
		if err != nil {
			log.Errorf("[%s ]Could not connect to ETCD: %v", database.DBUniqueName, err)
			return ret, err
		}
		kapi := client.NewKeysAPI(c)

		if database.DBType == DBTYPE_PATRONI_NAMESPACE_DISCOVERY {
			// all scopes, all DBs (regex filtering applies if defined)
			if len(database.DBName) > 0 {
				log.Errorf("Skipping Patroni entry %s - cannot specify a DB name when monitoring all scopes (regex patterns are supported though)", database.DBUniqueName)
				return ret, errors.New(fmt.Sprintf("Skipping Patroni entry %s - cannot specify a DB name when monitoring all scopes (regex patterns are supported though)", database.DBUniqueName))
			}
			if database.HostConfig.Namespace == "" {
				log.Errorf("Skipping Patroni entry %s - search 'namespace' not specified", database.DBUniqueName)
				return ret, errors.New(fmt.Sprintf("Skipping Patroni entry %s - search 'namespace' not specified", database.DBUniqueName))
			}
			log.Errorf("Scanning ETCD namespace %s for clusters to track...", database.HostConfig.Namespace)
			resp, err := kapi.Get(context.Background(), database.HostConfig.Namespace, &client.GetOptions{Recursive: true})
			if err != nil {
				log.Error("Could not read Patroni scopes from ETCD:", err)
				return ret, err
			}

			for _, node := range resp.Node.Nodes {
				log.Errorf("[%s] Patroni namespace discovery - found a scope from etcd: %+v", database.DBUniqueName, node.Key)
				scope := path.Base(node.Key) // Key="/service/batman"
				scopeMembers, err := extractEtcdScopeMembers(database, scope, kapi, true)
				if err != nil {
					continue
				}
				for _, sm := range scopeMembers {
					ret = append(ret, sm)
				}
			}
		} else {
			ret, err = extractEtcdScopeMembers(database, database.HostConfig.Scope, kapi, false)
			if err != nil {
				return ret, err
			}
		}
		lastFoundClusterMembers[database.DBUniqueName] = ret
	} else if database.HostConfig.DcsType == DCS_TYPE_ETCD_V3 {
		c, err := clientv3.New(cfgv3)
		if err != nil {
			log.Errorf("[%s ]Could not connect to ETCD: %v", database.DBUniqueName, err)
			return ret, err
		}
		kapi := clientv3.NewKV(c)
		if database.DBType == DBTYPE_PATRONI_NAMESPACE_DISCOVERY {
			// all scopes, all DBs (regex filtering applies if defined)
			if len(database.DBName) > 0 {
				log.Errorf("Skipping Patroni entry %s - cannot specify a DB name when monitoring all scopes (regex patterns are supported though)", database.DBUniqueName)
				return ret, errors.New(fmt.Sprintf("Skipping Patroni entry %s - cannot specify a DB name when monitoring all scopes (regex patterns are supported though)", database.DBUniqueName))
			}
			if database.HostConfig.Namespace == "" {
				log.Errorf("Skipping Patroni entry %s - search 'namespace' not specified", database.DBUniqueName)
				return ret, errors.New(fmt.Sprintf("Skipping Patroni entry %s - search 'namespace' not specified", database.DBUniqueName))
			}
			log.Errorf("Scanning ETCD namespace %s for clusters to track...", database.HostConfig.Namespace)
			resp, err := kapi.Get(context.Background(), database.HostConfig.Namespace, clientv3.WithFromKey())
			if err != nil {
				log.Error("Could not read Patroni scopes from ETCD:", err)
				return ret, err
			}

			for _, node := range resp.Kvs {
				log.Errorf("[%s] Patroni namespace discovery - found a scope from etcd: %+v", database.DBUniqueName, node.Key)
				scope := path.Base(string(node.Key)) // Key="/service/batman"
				scopeMembers, err := extractEtcdV3ScopeMembers(database, scope, kapi, true)
				if err != nil {
					continue
				}
				for _, sm := range scopeMembers {
					ret = append(ret, sm)
				}
			}
		} else {
			ret, err = extractEtcdV3ScopeMembers(database, database.HostConfig.Scope, kapi, false)
			if err != nil {
				return ret, err
			}
		}
		lastFoundClusterMembers[database.DBUniqueName] = ret
	}
	return ret, nil
}

func extractEtcdScopeMembers(database MonitoredDatabase, scope string, kapi client.KeysAPI, addScopeToName bool) ([]PatroniClusterMember, error) {
	var ret = make([]PatroniClusterMember, 0)
	var name string
	membersPath := path.Join(database.HostConfig.Namespace, scope, "members")

	resp, err := kapi.Get(context.Background(), membersPath, &client.GetOptions{Recursive: true})
	if err != nil {
		log.Errorf("Could not read Patroni members from ETCD for %s scope %s: %v", database.DBUniqueName, scope, err)
		return nil, err
	}
	log.Debugf("ETCD response for %s scope %s: %+v", database.DBUniqueName, scope, resp)

	for _, node := range resp.Node.Nodes {
		log.Debugf("Found a cluster member from etcd [%s:%s]: %+v", database.DBUniqueName, scope, node.Value)
		nodeData, err := jsonTextToStringMap(node.Value)
		if err != nil {
			log.Errorf("Could not parse ETCD node data for node \"%s\": %s", node, err)
			continue
		}
		role := nodeData["role"]
		connUrl := nodeData["conn_url"]
		if addScopeToName {
			name = scope + "_" + path.Base(node.Key)
		} else {
			name = path.Base(node.Key)
		}

		ret = append(ret, PatroniClusterMember{Scope: scope, ConnUrl: connUrl, Role: role, Name: name})
	}
	return ret, nil
}

func extractEtcdV3ScopeMembers(database MonitoredDatabase, scope string, kvapi clientv3.KV, addScopeToName bool) ([]PatroniClusterMember, error) {
	var ret = make([]PatroniClusterMember, 0)
	var name string
	membersPath := path.Join(database.HostConfig.Namespace, scope, "members")

	resp, err := kvapi.Get(context.Background(), membersPath, clientv3.WithFromKey())
	if err != nil {
		log.Errorf("Could not read Patroni members from ETCDV3 for %s scope %s: %v", database.DBUniqueName, scope, err)
		return nil, err
	}
	log.Debugf("ETCDV3 response for %s scope %s: %+v", database.DBUniqueName, scope, resp)

	for _, node := range resp.Kvs {
		log.Debugf("Found a cluster member from etcd [%s:%s]: %+v", database.DBUniqueName, scope, node.Value)
		nodeData, err := jsonTextToStringMap(string(node.Value))
		if err != nil {
			log.Errorf("Could not parse ETCD node data for node \"%s\": %s", node, err)
			continue
		}
		role := nodeData["role"]
		connUrl := nodeData["conn_url"]
		if addScopeToName {
			name = scope + "_" + path.Base(string(node.Key))
		} else {
			name = path.Base(string(node.Key))
		}

		ret = append(ret, PatroniClusterMember{Scope: scope, ConnUrl: connUrl, Role: role, Name: name})
	}
	return ret, nil
}

func ZookeeperGetClusterMembers(database MonitoredDatabase) ([]PatroniClusterMember, error) {
	var ret []PatroniClusterMember

	if len(database.HostConfig.DcsEndpoints) == 0 {
		return ret, errors.New("Missing Zookeeper connect info, make sure host config has a 'dcs_endpoints' key")
	}

	c, _, err := zk.Connect(database.HostConfig.DcsEndpoints, time.Second, zk.WithLogInfo(false))
	if err != nil {
		log.Error("Could not connect to Zookeeper", err)
		return ret, err
	}
	defer c.Close()

	members, _, err := c.Children(path.Join(database.HostConfig.Namespace, database.HostConfig.Scope, "members"))
	if err != nil {
		log.Error("Could not read Patroni members from Zookeeper:", err)
		return ret, err
	}

	for _, member := range members {
		log.Debugf("Found a cluster member from Zookeeper: %+v", member)
		keyData, _, err := c.Get(path.Join(database.HostConfig.Namespace, database.HostConfig.Scope, "members", member))
		if err != nil {
			log.Errorf("Could not read member (%s) info from Zookeeper:", member, err)
			continue
		}
		nodeData, err := jsonTextToStringMap(string(keyData))
		if err != nil {
			log.Errorf("Could not parse Zookeeper node data for node \"%s\": %s", member, err)
			continue
		}
		role := nodeData["role"]
		connUrl := nodeData["conn_url"]
		name := path.Base(member)

		ret = append(ret, PatroniClusterMember{Scope: database.HostConfig.Scope, ConnUrl: connUrl, Role: role, Name: name})
	}

	return ret, nil
}

func ResolveDatabasesFromPatroni(ce MonitoredDatabase) ([]MonitoredDatabase, error) {
	md := make([]MonitoredDatabase, 0)
	cm := make([]PatroniClusterMember, 0)
	var err error
	var ok bool
	var dbUnique string

	if ce.DBType == DBTYPE_PATRONI_NAMESPACE_DISCOVERY && ce.HostConfig.DcsType != DCS_TYPE_ETCD && ce.HostConfig.DcsType != DCS_TYPE_ETCD_V3 {
		log.Warningf("Skipping Patroni monitoring entry \"%s\" as currently only ETCD namespace scanning is supported...", ce.DBUniqueName)
		return md, nil
	}
	log.Debugf("Resolving Patroni nodes for \"%s\" from HostConfig: %+v", ce.DBUniqueName, ce.HostConfig)
	if ce.HostConfig.DcsType == DCS_TYPE_ETCD || ce.HostConfig.DcsType == DCS_TYPE_ETCD_V3 {
		cm, err = EtcdGetClusterMembers(ce)
	} else if ce.HostConfig.DcsType == DCS_TYPE_ZOOKEEPER {
		cm, err = ZookeeperGetClusterMembers(ce)
	} else if ce.HostConfig.DcsType == DCS_TYPE_CONSUL {
		cm, err = ConsulGetClusterMembers(ce)
	} else {
		log.Error("unknown DCS", ce.HostConfig.DcsType)
		return md, errors.New("unknown DCS")
	}
	if err != nil {
		log.Warningf("Failed to get info from DCS for %s, using previous member info if any", ce.DBUniqueName)
		cm, ok = lastFoundClusterMembers[ce.DBUniqueName]
		if ok { // mask error from main loop not to remove monitored DBs due to "jitter"
			err = nil
		}
	} else {
		lastFoundClusterMembers[ce.DBUniqueName] = cm
	}
	if len(cm) == 0 {
		log.Warningf("No Patroni cluster members found for cluster [%s:%s]", ce.DBUniqueName, ce.HostConfig.Scope)
		return md, nil
	}
	log.Infof("Found %d Patroni members for entry %s", len(cm), ce.DBUniqueName)

	for _, m := range cm {
		log.Infof("Processing Patroni cluster member [%s:%s]", ce.DBUniqueName, m.Name)
		if ce.OnlyIfMaster && m.Role != "master" {
			log.Infof("Skipping over Patroni cluster member [%s:%s] as not a master", ce.DBUniqueName, m.Name)
			continue
		}
		host, port, err := ParseHostAndPortFromJdbcConnStr(m.ConnUrl)
		if err != nil {
			log.Errorf("Could not parse Patroni conn str \"%s\" [%s:%s]: %v", m.ConnUrl, ce.DBUniqueName, m.Scope, err)
			continue
		}
		if ce.OnlyIfMaster {
			dbUnique = ce.DBUniqueName
			if ce.DBType == DBTYPE_PATRONI_NAMESPACE_DISCOVERY {
				dbUnique = ce.DBUniqueName + "_" + m.Scope
			}
		} else {
			dbUnique = ce.DBUniqueName + "_" + m.Name
		}
		if ce.DBName != "" {
			md = append(md, MonitoredDatabase{
				DBUniqueName:      dbUnique,
				DBUniqueNameOrig:  ce.DBUniqueName,
				DBName:            ce.DBName,
				Host:              host,
				Port:              port,
				User:              ce.User,
				Password:          ce.Password,
				PasswordType:      ce.PasswordType,
				SslMode:           ce.SslMode,
				SslRootCAPath:     ce.SslRootCAPath,
				SslClientCertPath: ce.SslClientCertPath,
				SslClientKeyPath:  ce.SslClientKeyPath,
				StmtTimeout:       ce.StmtTimeout,
				Metrics:           ce.Metrics,
				PresetMetrics:     ce.PresetMetrics,
				IsSuperuser:       ce.IsSuperuser,
				CustomTags:        ce.CustomTags,
				HostConfig:        ce.HostConfig,
				DBType:            "postgres"})
			continue
		} else {
			c, err := GetPostgresDBConnection("", host, port, "template1", ce.User, ce.Password,
				ce.SslMode, ce.SslRootCAPath, ce.SslClientCertPath, ce.SslClientKeyPath)
			if err != nil {
				log.Errorf("Could not contact Patroni member [%s:%s]: %v", ce.DBUniqueName, m.Scope, err)
				continue
			}
			defer c.Close()
			sql := `select datname::text as datname,
					quote_ident(datname)::text as datname_escaped
					from pg_database
					where not datistemplate
					and datallowconn
					and has_database_privilege (datname, 'CONNECT')
					and case when length(trim($1)) > 0 then datname ~ $2 else true end
					and case when length(trim($3)) > 0 then not datname ~ $4 else true end`

			data, err := DBExecRead(c, ce.DBUniqueName, sql, ce.DBNameIncludePattern, ce.DBNameIncludePattern, ce.DBNameExcludePattern, ce.DBNameExcludePattern)
			if err != nil {
				log.Errorf("Could not get DB name listing from Patroni member [%s:%s]: %v", ce.DBUniqueName, m.Scope, err)
				continue
			}

			for _, d := range data {
				md = append(md, MonitoredDatabase{
					DBUniqueName:      dbUnique + "_" + d["datname_escaped"].(string),
					DBUniqueNameOrig:  dbUnique,
					DBName:            d["datname"].(string),
					Host:              host,
					Port:              port,
					User:              ce.User,
					Password:          ce.Password,
					PasswordType:      ce.PasswordType,
					SslMode:           ce.SslMode,
					SslRootCAPath:     ce.SslRootCAPath,
					SslClientCertPath: ce.SslClientCertPath,
					SslClientKeyPath:  ce.SslClientKeyPath,
					StmtTimeout:       ce.StmtTimeout,
					Metrics:           ce.Metrics,
					PresetMetrics:     ce.PresetMetrics,
					IsSuperuser:       ce.IsSuperuser,
					CustomTags:        ce.CustomTags,
					HostConfig:        ce.HostConfig,
					DBType:            "postgres"})
			}
		}

	}

	return md, err
}
