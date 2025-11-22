---
title: Javascript 개념 및 사용법
tags: Javascript
key: page-javascript_concepts_usage
categories: [Development, Programming Fundamentals]
author: hyoeun
cover_size: md
---

* Javascript는 절차지향적인(c언어 등) 언어들과는 다르게 특정 코드의 연산이 끝나지 않아도 다음 코드를 먼저 실행하는 특성을 지닌다.

```javascript
console.log('Hello');

setTimeout(function () {
	console.log('Bye');
}, 3000);

console.log('Hello Again');

//출력 결과

//Hello
//Hello Again
//Bye
```