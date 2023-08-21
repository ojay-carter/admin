
const jwt = require('jsonwebtoken');
const axios = require('axios')


module.exports = {
    isUserAuthenticated: (req, res, next) => {
        if (req.isAuthenticated()) {
            next();
        }
        else{
            res.redirect('/auth');
        }
    }, 

    
    loggedIn: async (req, res, next) => {
        if (req.session.loggedin) {
            
            try {
                const response = await axios.get('http://localhost:9090/admin/verify', {
                    headers: {
                        "Content-type": "application/json",
                        "Authorization": `Bearer ${req.session.token}`
                    }
                });
    
                if (response.status === 200) {
                    if (req.session.email == response.data.user.email) {
                        req.session.save();
                        next();
                    } else {
                        res.redirect('/auth');
                    }
                } else {
                    res.redirect('/auth');
                }
            } catch (error) {
                res.redirect('/auth');
            }
        } else {
            res.redirect('/auth');
        }
    },

    xloggedIn: (req, res, next) => {
        if(req.session.loggedin || req.session.email){
            req.session.save();
            next();
        }else{
            res.redirect('/auth');
        }
    },


    isEmpty: function(obj) {
        for (let key in obj) {
            if(obj.hasOwnProperty(key)) {
                return false;
            }
        }

        return true;
    },

    // Middleware to authenticate API key
    authenticateAPIKey: function (req, res, next) {
        // Get the API key from the request headers or query parameters
        const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    
        if (!apiKey) {
        return res.status(401).json({ error: 'API key is missing' });
        }
    
        // Verify and decode the JWT token
        jwt.verify(apiKey, process.env.SECRET, (error, decoded) => {
        if (error) {
            return res.status(401).json({ error: 'Invalid API key' });
        }
    
        // Pass the decoded user information to the next middleware or route
        req.user = decoded;
        next();
        });
    }

}