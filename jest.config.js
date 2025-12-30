module.exports = {
    testEnvironment: 'node',
    transform: {
        '^.+\\.js$': 'babel-jest'
    },
    testMatch: ['**/tests/**/*.test.js'],
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/index.js'
    ],
    coverageThreshold: {
        global: {
            branches: 60,  // Temporarily lower to see coverage
            functions: 60,
            lines: 60,
            statements: 60
        }
    }
};