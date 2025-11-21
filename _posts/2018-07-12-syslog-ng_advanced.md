---
title: Syslog-Ng 심화 사용
tags: Syslog-Ng Tools
key: page-syslog_ng_advanced_usage
categories: [Development, SysOps & Infrastructure]
author: hyoeun
---
### if, elif, and else 구문
* 2가지 형식이 가능하다.

1. if 조건문 안에는 filter expression만 가능하고 foo가 포함되어 있지 않으면 else구문으로 빠진다.
```conf
if (message('foo')) {
    parser { date-parser(); };
} else {
    ...
};
```

2. if 구문 안에서 date-parser가 실패하거나 foo가 없으면 else로 빠진다.
```conf
if {
    filter { message('foo')); };
    parser { date-parser(); };
} else {
    ...
};
```

### inline 방식
* 다음 2개의 코드는 동일하게 작동한다.
    
    ```conf
    source s_local {
        system();
        internal();
    };
    destination d_local {
        file("/var/log/messages");
    };
    log {
        source(s_local);
        destination(d_local);
    };
    ```

    ```conf
    log {
        source {
            system();
            internal();
        };
        destination {
            file("/var/log/messages");
        };
    };
    ```

### channel

* object안에 다시 object를 넣을 수 있다.
```conf
source s_apache {
    channel {
        source {
            file("/var/log/apache/error.log");
        };
        parser(p_apache_parser);
    };
};
log {
    source(s_apache); ...
};
```

### 전역변수 설정
```conf
@define mypath "/opt/myapp/logs"
source s_myapp_1 {
    file("`mypath`/access.log" follow-freq(1));
};
source s_myapp_2 {
    file("`mypath`/error.log" follow-freq(1));
};
source s_myapp_3 {
    file("`mypath`/debug.log" follow-freq(1));
};
```

