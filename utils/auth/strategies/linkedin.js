const passport = require('passport');
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
const axios = require('axios');
const boom = require('@hapi/boom');

const { config } = require('../../../config');

passport.use(
  new LinkedInStrategy(
    {
      clientID: config.linkedinClientId,
      clientSecret: config.linkedinClientSecret,
      callbackURL: '/auth/linkedin/callback',
      scope: ['r_emailaddress', 'r_liteprofile'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const { data, status } = await axios({
          url: `${config.apiUrl}/api/auth/sign-provider`,
          method: 'post',
          data: {
            name: profile.displayName,
            email: profile.emails[0].value,
            password: profile.id,
            apiKeyToken: config.apiKeyToken,
          },
        });

        if (!data || status !== 200) {
          done(boom.unauthorized(), false);
        }

        done(null, data);
      } catch (err) {
        done(err);
      }
    },
  ),
);
