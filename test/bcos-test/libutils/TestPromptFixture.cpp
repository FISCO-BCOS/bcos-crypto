/*
 *  Copyright (C) 2021 FISCO BCOS.
 *  SPDX-License-Identifier: Apache-2.0
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @file: TestPromptFixture.cpp
 */

#include "TestPromptFixture.h"
#include <boost/test/unit_test.hpp>


using namespace std;
using namespace bcos;
using namespace bcos::test;
// output the name of cases when running a test-suite
void TestPrompt::initTest(size_t _maxTests)
{
    m_currentTestName = "unknown";
    m_currentTestFileName = string();
    m_startTime = utcTime();
    m_currentTestCaseName = boost::unit_test::framework::current_test_case().p_name;
    std::cout << "===== BCOS Test Case : " + m_currentTestCaseName << "=====" << std::endl;
    m_maxTests = _maxTests;
    m_currTest = 0;
}

// release resources when testing finished
void TestPrompt::finishTest()
{
    execTimeName res;
    res.first = (double)(utcTime() - m_startTime);
    res.second = caseName();
    std::cout << "#### Run " << res.second << " time elapsed: " << res.first << std::endl;
    m_execTimeResults.push_back(res);
}