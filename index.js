const winston = require('winston');

class ExpressLogger {
    constructor(httpContext) {
        this.setLogLevels();
        this.winstonLogger = winston.createLogger({
            levels: winston.config.syslog.levels,
            transports: [
                new winston.transports.Console({
                    level: this.getLogLevel(),
                    showLevel: false,
                }),
            ],
            exitOnError: false,
        });

        this.httpContext = httpContext;
    }

    setup() {
        return (req, res, next) => {
            // bind httpContext to req and res
            this.httpContext.ns.bindEmitter(req);
            this.httpContext.ns.bindEmitter(res);
            // add request id and request start time to context
            this.httpContext.set('request-id', req.headers['request-id']);
            this.httpContext.set('request-start-time', Date.now());

            // Updating service counter in the header;
            const counter = req.headers['Service-Counter'] ? req.headers['Service-Counter'] : 0;
            req.headers['Service-Counter'] = counter + 1;

            // log request
            this.winstonLogger.crit(this.formatRequestLog(req));
            this.winstonLogger.crit(this.formatMessage('CRITICAL', `Headers from PAG ${JSON.stringify(req.headers)}`));

            res.on('finish', () => {
                // log res
                if (res.statusCode < 400) { this.winstonLogger.crit(this.formatResponseLog('CRITICAL', res)); } else {
                    this.winstonLogger.crit(this.formatMessage('CRITICAL', '************* ERROR ************'));
                    this.winstonLogger.crit(this.formatResponseLog('CRITICAL', res));
                }
            });
            next();
        };
    }

    setLogLevels() {
        this.LEVELS = {
            emerg: 0,
            alert: 1,
            crit: 2,
            error: 3,
            warning: 4,
            notice: 5,
            info: 6,
            debug: 7,
        };
    }

    getLogLevel() {
        const levelInEnv = (
            process.env.LOG_LEVEL
            && Object.keys(this.LEVELS).indexOf(process.env.LOG_LEVEL.trim().toLowerCase())
        );
        if (levelInEnv) {
            return process.env.LOG_LEVEL.trim().toLowerCase();
        }
        return process.env.STAGE === 'prod' ? 'error' : 'debug';
    }

    formatMessage(level, message) {
        const reqId = this.httpContext.get('request-id');
        return {
            Service: 'Init',
            'Request-Id': reqId,
            Message: message,
            level,
        };
    }

    formatResponseLog(level, response) {
        const jsonMessage = this.formatMessage(level, response.statusMessage);
        const timeTaken = Date.now() - this.httpContext.get('request-start-time');
        jsonMessage.TimeTaken = timeTaken;
        jsonMessage.StatusCode = response.statusCode;
        return jsonMessage;
    }

    formatRequestLog(req) {
        const jsonMessage = this.formatMessage('CRITICAL');
        jsonMessage.Method = req.method;
        jsonMessage.Url = req.originalUrl || req.url;
        jsonMessage['Request-Size'] = req.headers['content-length'] ? req.headers['content-length'] : 'Not Sent By Client';
        jsonMessage['Service-Counter'] = req.headers['Service-Counter'];
        const body = { ...req.body };
        jsonMessage.Body = JSON.stringify(body);
        return jsonMessage;
    }

    error(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.error(this.formatMessage('ERROR', combinedMessage));
    }

    warning(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.warning(this.formatMessage('WARNING', combinedMessage));
    }

    info(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.info(this.formatMessage('INFO', combinedMessage));
    }

    verbose(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.debug(this.formatMessage('DEBUG', combinedMessage));
    }

    debug(...message) {
        const combinedMessage = message.join(' ');
        this.winstonLogger.debug(this.formatMessage('DEBUG', combinedMessage));
    }
}

module.exports = ExpressLogger;
